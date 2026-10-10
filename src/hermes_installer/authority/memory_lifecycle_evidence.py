"""Root-produced source closure and semantic readiness for selected memory.

Only the active protected profile, launch recipe, ArtifactCatalog, retained
process identity and fixed memory route recipes supply authority here.  These
receipts are short-lived observations; a receipt handle is never evidence by
itself and every resolve reopens and rehashes the selected bytes.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from hermes_installer.artifacts import ArtifactCatalog
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.memory.compound import build_memory_request, validate_step_outcome
from hermes_installer.memory.enrollment import MemoryServiceEnrollment
from hermes_installer.memory.namespace_connector import MemoryNamespaceConnector
from hermes_installer.protected_enrollment import RootJournalSelection


class RootMemoryEvidenceDenied(PermissionError):
    """Selected memory source or semantic evidence is unavailable or stale."""


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _managed_identity_digest(lease: Any) -> str:
    body = {
        "process_id": lease.process_id, "profile_id": lease.profile_id,
        "generation": lease.generation, "uid": lease.uid, "gid": lease.gid,
        "pid": lease.pid, "start_ticks": lease.start_ticks,
        "executable_device": lease.executable_device,
        "executable_inode": lease.executable_inode,
        "executable_sha256": lease.executable_sha256,
        "cgroup_identity": lease.cgroup_identity,
        "mount_namespace_inode": lease.mount_namespace_inode,
        "network_namespace_inode": lease.network_namespace_inode,
    }
    return _digest(json.dumps(body, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True).encode("ascii"))


def _safe_id(value: Any) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 128
            or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-" for ch in value)):
        raise RootMemoryEvidenceDenied("memory evidence selector is malformed")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class RootMemoryPrestartReceipt:
    schema: int
    receipt_handle: str
    memory_enrollment_id: str
    provider: str
    backend_variant: str
    profile_id: str
    namespace_id: str
    principal_id: str
    service_enrollment_id: str
    service_generation: str
    enclosing_service_generation_digest: str
    memory_owner_generation: int
    start_operation_id: str
    operation_recipe_sha256: str
    source_closure_sha256: str
    artifact_records: tuple[Mapping[str, Any], ...]
    config_records: tuple[Mapping[str, Any], ...]
    source_revision: str
    runtime_receipt_handles: tuple[str, ...]
    enablement_selection_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _selection_digest: str = field(repr=False)
    _revocation_epoch: int = field(repr=False)
    _is_current: Callable[[], bool] = field(repr=False, compare=False)

    def is_current(self) -> bool:
        try:
            return time.monotonic() < self.expires_monotonic and self._is_current()
        except Exception:
            return False

    def __repr__(self) -> str:
        return "RootMemoryPrestartReceipt(<root-private>)"


class RootMemoryPrestartReceiptRegistry:
    """Reopen the exact installed profile/runtime closure and retain a fresh receipt.

    Receipt handles from the active lifecycle binding must be records issued by
    this registry. Legacy strings fail closed. The registry is attached to one
    active root generation and one journal identity.
    """

    def __init__(self, *, active_bindings: RootRuntimeBindings,
                 artifact_catalog: ArtifactCatalog, managed_process_custody: Any,
                 root_journal: RootJournalSelection,
                 monotonic: Callable[[], float] = time.monotonic,
                 expected_uid: int = 0):
        if (os.geteuid() != expected_uid or expected_uid != 0
                or not isinstance(active_bindings, RootRuntimeBindings)
                or artifact_catalog is not active_bindings.artifact_catalog
                or managed_process_custody is not active_bindings.process_manager
                or not isinstance(root_journal, RootJournalSelection)
                or root_journal.service_generation_digest != active_bindings.service_generation_digest
                or not callable(monotonic)):
            raise RootMemoryEvidenceDenied("root active source evidence bindings are unavailable")
        self.bindings = active_bindings
        self.artifact_catalog = artifact_catalog
        self.custody = managed_process_custody
        self.journal = root_journal
        self.monotonic = monotonic
        self.expected_uid = expected_uid
        self._lock = threading.RLock()
        self._receipts: dict[str, RootMemoryPrestartReceipt] = {}
        self._aliases: dict[str, RootMemoryPrestartReceipt] = {}
        self._latest: dict[str, str] = {}

    def _check_journal(self) -> None:
        if (os.geteuid() != self.expected_uid
                or self.bindings.service_generation_digest != self.journal.service_generation_digest):
            raise RootMemoryEvidenceDenied("memory source journal belongs to a stale root generation")
        try:
            current = self.bindings.resolve_root_journal(
                self.journal.root_id,
                expected_active_generation_digest=self.bindings.service_generation_digest,
            )
            info = self.journal.path.stat(follow_symlinks=False)
        except Exception:
            raise RootMemoryEvidenceDenied("active memory source journal is unavailable") from None
        if (current != self.journal or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != self.expected_uid or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (self.journal.device, self.journal.inode)):
            raise RootMemoryEvidenceDenied("active memory source journal identity changed")

    def _receipt_directory(self) -> Path:
        """Create the private, journal-relative receipt store without following links."""
        self._check_journal()
        parent = self.journal.path / "memory-lifecycle"
        directory = parent / "prestart-receipts"
        try:
            parent.mkdir(mode=0o700, exist_ok=True)
            directory.mkdir(mode=0o700, exist_ok=True)
            for path in (parent, directory):
                info = path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or info.st_uid != self.expected_uid
                        or stat.S_IMODE(info.st_mode) != 0o700):
                    raise ValueError
            if parent.parent != self.journal.path:
                raise ValueError
            return directory
        except Exception:
            raise RootMemoryEvidenceDenied("root memory prestart receipt store custody is invalid") from None

    @staticmethod
    def _alias_filename(handle: str) -> str:
        return hashlib.sha256(handle.encode("ascii")).hexdigest() + ".json"

    def _persist_receipt(self, alias: str, receipt: RootMemoryPrestartReceipt) -> None:
        directory = self._receipt_directory()
        document = {
            "schema": 1, "alias": alias, "receipt_handle": receipt.receipt_handle,
            "memory_enrollment_id": receipt.memory_enrollment_id,
            "source_closure_sha256": receipt.source_closure_sha256,
            "runtime_receipt_handles": list(receipt.runtime_receipt_handles),
            "artifact_records": [dict(row) for row in receipt.artifact_records],
            "issued_monotonic": receipt.issued_monotonic,
        }
        body = _canonical(document)
        if len(body) > 1024 * 1024:
            raise RootMemoryEvidenceDenied("root memory source receipt exceeds its bound")
        name = self._alias_filename(alias)
        temporary = f".{name}.{secrets.token_hex(8)}.tmp"
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        fd = -1
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory_fd)
            offset = 0
            while offset < len(body):
                offset += os.write(fd, body[offset:])
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.rename(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        except Exception:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except OSError:
                pass
            raise RootMemoryEvidenceDenied("root memory source receipt could not be retained") from None
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(directory_fd)

    def _load_receipt_alias(self, alias: str, enrollment_id: str) -> RootMemoryPrestartReceipt:
        directory = self._receipt_directory()
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        fd = -1
        try:
            fd = os.open(self._alias_filename(alias), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory_fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > 1024 * 1024):
                raise ValueError
            data = bytearray()
            while len(data) <= 1024 * 1024:
                block = os.read(fd, min(64 * 1024, 1024 * 1024 + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            if len(data) != info.st_size:
                raise ValueError
            value = json.loads(bytes(data).decode("utf-8"))
            required = {"schema", "alias", "receipt_handle", "memory_enrollment_id",
                        "source_closure_sha256", "runtime_receipt_handles", "artifact_records",
                        "issued_monotonic"}
            if (not isinstance(value, dict) or set(value) != required or value["schema"] != 1
                    or value["alias"] != alias or value["memory_enrollment_id"] != enrollment_id
                    or type(value["runtime_receipt_handles"]) is not list
                    or type(value["artifact_records"]) is not list
                    or type(value["issued_monotonic"]) not in (int, float)
                    or not math.isfinite(value["issued_monotonic"])):
                raise ValueError
            fresh = self._derive(enrollment_id, value["receipt_handle"], self.monotonic())
            if (fresh.source_closure_sha256 != value["source_closure_sha256"]
                    or [dict(row) for row in fresh.artifact_records] != value["artifact_records"]
                    or list(fresh.runtime_receipt_handles) != value["runtime_receipt_handles"]
                    or not fresh.is_current()):
                raise ValueError
            return fresh
        except Exception:
            raise RootMemoryEvidenceDenied("retained prestart receipt is invalid or stale") from None
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(directory_fd)

    @classmethod
    def from_root_runtime(cls, active_bindings: RootRuntimeBindings,
                          artifact_catalog: ArtifactCatalog,
                          managed_process_custody: Any,
                          root_journal: RootJournalSelection, **kwargs: Any
                          ) -> "RootMemoryPrestartReceiptRegistry":
        return cls(active_bindings=active_bindings, artifact_catalog=artifact_catalog,
                   managed_process_custody=managed_process_custody,
                   root_journal=root_journal, **kwargs)

    def _derive(self, memory_enrollment_id: str, receipt_handle: str,
                issued: float) -> RootMemoryPrestartReceipt:
        digest = self.bindings.service_generation_digest
        enrollment = self.bindings.resolve_memory_enrollment(
            memory_enrollment_id, service_generation_digest=digest)
        if type(enrollment) is not MemoryServiceEnrollment or enrollment.lifecycle_binding is None:
            raise RootMemoryEvidenceDenied("active memory lifecycle enrollment is unavailable")
        # The protected generation must link the same explicit root installer
        # service-choice observation that enabled this exact lifecycle recipe.
        # Private-route and capture selections are deliberately not accepted.
        resolve_enablement = getattr(
            self.bindings, "resolve_current_memory_service_enablement_selection", None)
        if not callable(resolve_enablement):
            raise RootMemoryEvidenceDenied(
                "root memory service enablement selection registry is unavailable")
        try:
            enablement = resolve_enablement(
                enrollment, service_generation_digest=digest)
        except Exception:
            raise RootMemoryEvidenceDenied(
                "current root memory service enablement selection is unavailable") from None
        expected_enablement = {
            "principal_id": enrollment.principal_id,
            "profile_id": enrollment.profile_id,
            "namespace_id": enrollment.namespace_identity,
            "provider": enrollment.provider,
            "backend_variant": enrollment.backend_variant,
            "service_enrollment_id": enrollment.service_enrollment_id,
            "service_generation": enrollment.service_generation,
            "memory_owner_generation": enrollment.memory_owner_generation,
            "start_operation_id": enrollment.lifecycle_binding.start_operation_id,
            "state": "enabled",
        }
        if (type(enablement) is not MappingProxyType
                or set(enablement) != {
                    "selection_handle", "choice_observation_id", "principal_id", "profile_id",
                    "namespace_id", "provider", "backend_variant", "service_enrollment_id",
                    "service_generation", "memory_owner_generation", "start_operation_id",
                    "policy_revision", "selection_digest", "state", "revocation_epoch"}
                or any(enablement.get(key) != value
                       for key, value in expected_enablement.items())
                or not isinstance(enablement.get("selection_handle"), str)
                or not enablement["selection_handle"]
                or not isinstance(enablement.get("choice_observation_id"), str)
                or not enablement["choice_observation_id"]
                or not isinstance(enablement.get("selection_digest"), str)
                or len(enablement["selection_digest"]) != 64
                or not isinstance(enablement.get("policy_revision"), str)
                or not enablement["policy_revision"]
                or type(enablement.get("revocation_epoch")) is not int
                or enablement["revocation_epoch"] < 0):
            raise RootMemoryEvidenceDenied(
                "root memory service enablement selection does not join the active recipe")
        lifecycle = enrollment.lifecycle_binding
        if (lifecycle.service_enrollment_id != enrollment.service_enrollment_id
                or lifecycle.service_generation != enrollment.service_generation):
            raise RootMemoryEvidenceDenied("memory lifecycle recipe generation is stale")
        service = self.bindings.enrollment_catalog.resolve(
            enrollment.service_enrollment_id, enrollment.service_generation)
        managed = self.bindings.process_profiles.get(service.profile_id)
        if (managed is None or managed.enrollment_id != service.enrollment_id
                or managed.generation != service.generation
                or managed.profile_id != service.profile_id
                or managed.owner_uid != service.service_uid or managed.owner_gid != service.service_gid
                or managed.artifact_root is None):
            raise RootMemoryEvidenceDenied("selected memory managed profile is stale")
        resolved = self.bindings.enrollment_catalog.resolve_launch_recipe(
            service.enrollment_id, service.generation, lifecycle.start_operation_id)
        recipe = resolved.recipe
        if (resolved.profile_id != service.profile_id or resolved.service_uid != service.service_uid
                or recipe.parameter_schema_id != "no-caller-parameters-v1"
                or resolved.parameter_schema.fields):
            raise RootMemoryEvidenceDenied("memory start recipe is not the exact empty-parameter operation")

        pins: dict[str, tuple[str, str]] = {}
        executable_spec = self.artifact_catalog.artifacts.get(recipe.executable_artifact_id)
        if executable_spec is None or executable_spec.sha256 != recipe.executable_sha256:
            raise RootMemoryEvidenceDenied("selected memory executable is not catalog-pinned")
        pins[executable_spec.artifact_id] = (executable_spec.sha256, "executable")
        for artifact_id in managed.child_artifact_refs:
            spec = self.artifact_catalog.artifacts.get(artifact_id)
            if spec is None or managed.child_artifact_refs[artifact_id] != spec.sha256:
                raise RootMemoryEvidenceDenied("selected memory runtime artifact pin is invalid")
            pins[artifact_id] = (spec.sha256, "runtime")
        for artifact_id, sha256 in recipe.child_artifact_refs.items():
            spec = self.artifact_catalog.artifacts.get(artifact_id)
            if spec is None or spec.sha256 != sha256:
                raise RootMemoryEvidenceDenied("selected memory child artifact pin is invalid")
            role = "config" if "config" in artifact_id.casefold() else "engine"
            pins[artifact_id] = (sha256, role)
        artifact_records = []
        for artifact_id, (sha256, role) in sorted(pins.items()):
            fd = -1
            try:
                resolved_artifact = self.artifact_catalog.resolve(
                    artifact_id, sha256, managed.artifact_root, expected_uid=self.expected_uid)
                before = resolved_artifact.path.lstat()
                fd = os.open(resolved_artifact.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                        or info.st_nlink != 1 or info.st_mode & 0o222
                        or info.st_size != resolved_artifact.size_bytes
                        or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)):
                    raise ValueError
                hasher = hashlib.sha256()
                total = 0
                while True:
                    chunk = os.read(fd, 64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > resolved_artifact.size_bytes:
                        raise ValueError
                    hasher.update(chunk)
                after = os.fstat(fd)
                if ((after.st_dev, after.st_ino, after.st_size) !=
                        (info.st_dev, info.st_ino, info.st_size)
                        or total != resolved_artifact.size_bytes or hasher.hexdigest() != sha256):
                    raise ValueError
                relative = resolved_artifact.path.relative_to(managed.artifact_root).as_posix()
            except Exception:
                raise RootMemoryEvidenceDenied("selected memory artifact bytes or custody changed") from None
            finally:
                if fd >= 0:
                    os.close(fd)
            artifact_records.append(MappingProxyType({
                "artifact_id": artifact_id, "sha256": sha256,
                "size_bytes": info.st_size, "role": role,
                "relative_member_path": relative, "device": info.st_dev,
                "inode": info.st_ino, "uid": info.st_uid, "gid": info.st_gid,
                "mode": stat.S_IMODE(info.st_mode),
            }))
        recipe_doc = {
            "operation_id": recipe.operation_id,
            "executable_artifact_id": recipe.executable_artifact_id,
            "executable_sha256": recipe.executable_sha256,
            "argv_recipe": [dict(token) for token in recipe.argv_recipe],
            "cwd_root_id": recipe.cwd_root_id, "cwd_subpath": recipe.cwd_subpath,
            "environment": dict(recipe.environment),
            "child_artifact_refs": dict(recipe.child_artifact_refs),
            "parameter_schema_id": recipe.parameter_schema_id,
        }
        recipe_sha = _digest(_canonical(recipe_doc))
        config_records = tuple(dict(record) for record in artifact_records
                                if record["role"] == "config")
        closure_sha = _digest(_canonical({
            "memory_enrollment_id": memory_enrollment_id,
            "provider": enrollment.provider, "backend_variant": enrollment.backend_variant,
            "profile_id": enrollment.profile_id, "namespace_id": enrollment.namespace_identity,
            "principal_id": enrollment.principal_id,
            "service_enrollment_id": enrollment.service_enrollment_id,
            "service_generation": enrollment.service_generation,
            "service_generation_digest": digest,
            "memory_owner_generation": enrollment.memory_owner_generation,
            "start_operation_id": lifecycle.start_operation_id,
            "operation_recipe_sha256": recipe_sha,
            "artifact_records": [dict(record) for record in artifact_records],
            "config_records": list(config_records),
            "source_revision": enrollment.source_revision,
            "receipt_handles": list(lifecycle.prestart_receipt_handles),
            "enablement_selection_handle": enablement["selection_handle"],
            "enablement_selection_digest": enablement["selection_digest"],
            "enablement_revocation_epoch": enablement["revocation_epoch"],
        }))
        expires = min(issued + 30.0, issued + lifecycle.original_deadline_seconds)
        if expires <= issued:
            raise RootMemoryEvidenceDenied("memory prestart source lease is exhausted")

        def current() -> bool:
            try:
                self._check_journal()
                now_digest = self.bindings.service_generation_digest
                if now_digest != digest:
                    return False
                fresh = self.bindings.resolve_memory_enrollment(
                    memory_enrollment_id, service_generation_digest=digest)
                if fresh != enrollment:
                    return False
                live = self._derive_without_callback(fresh)
                return (live[0] == recipe_sha and live[1] == tuple(
                    (row["artifact_id"], row["sha256"], row["device"], row["inode"])
                    for row in artifact_records)
                    and live[2:] == (enablement["selection_handle"],
                                     enablement["selection_digest"],
                                     enablement["revocation_epoch"]))
            except Exception:
                return False

        return RootMemoryPrestartReceipt(
            schema=1, receipt_handle=receipt_handle,
            memory_enrollment_id=memory_enrollment_id,
            provider=enrollment.provider, backend_variant=enrollment.backend_variant,
            profile_id=enrollment.profile_id, namespace_id=enrollment.namespace_identity,
            principal_id=enrollment.principal_id,
            service_enrollment_id=enrollment.service_enrollment_id,
            service_generation=enrollment.service_generation,
            enclosing_service_generation_digest=digest,
            memory_owner_generation=enrollment.memory_owner_generation,
            start_operation_id=lifecycle.start_operation_id,
            operation_recipe_sha256=recipe_sha, source_closure_sha256=closure_sha,
            artifact_records=tuple(artifact_records),
            config_records=tuple(MappingProxyType(record) for record in config_records),
            source_revision=enrollment.source_revision,
            runtime_receipt_handles=tuple(lifecycle.prestart_receipt_handles),
            enablement_selection_handle=enablement["selection_handle"], issued_monotonic=issued,
            expires_monotonic=expires,
            _selection_digest=enablement["selection_digest"],
            _revocation_epoch=enablement["revocation_epoch"], _is_current=current,
        )

    def _derive_without_callback(self, enrollment: MemoryServiceEnrollment) -> tuple[Any, ...]:
        # Reuse the exact derivation with a throwaway handle, then compare the
        # immutable facts. The callback closes over no caller-selected fields.
        receipt = self._derive(enrollment.target_id, "currentness-check", self.monotonic())
        rows = tuple((item["artifact_id"], item["sha256"], item["device"], item["inode"])
                     for item in receipt.artifact_records)
        return (receipt.operation_recipe_sha256, rows, receipt.enablement_selection_handle,
                receipt._selection_digest, receipt._revocation_epoch)

    def observe_selected_prestart(self, memory_enrollment_id: str) -> str:
        """Observe and retain a fresh actual source closure for the active choice."""
        if os.geteuid() != self.expected_uid:
            raise RootMemoryEvidenceDenied("memory prestart source observation requires root")
        self._check_journal()
        selected = _safe_id(memory_enrollment_id)
        now = self.monotonic()
        handle = secrets.token_urlsafe(32)
        receipt = self._derive(selected, handle, now)
        if not receipt.is_current():
            raise RootMemoryEvidenceDenied("memory source closure changed during observation")
        with self._lock:
            self._receipts[handle] = receipt
            # Active lifecycle handles are only aliases into a closure that
            # was freshly re-opened above; they are never accepted alone.
            for source_handle in receipt.runtime_receipt_handles:
                self._aliases[source_handle] = receipt
            self._latest[selected] = handle
        self._persist_receipt(handle, receipt)
        for source_handle in receipt.runtime_receipt_handles:
            self._persist_receipt(source_handle, receipt)
        return handle

    def resolve_selected_prestart(self, receipt_handle: str,
                                  memory_enrollment_id: str) -> RootMemoryPrestartReceipt:
        self._check_journal()
        handle = _safe_id(receipt_handle)
        selected = _safe_id(memory_enrollment_id)
        with self._lock:
            receipt = self._receipts.get(handle) or self._aliases.get(handle)
        if (type(receipt) is RootMemoryPrestartReceipt
                and receipt.memory_enrollment_id == selected and receipt.is_current()):
            return receipt
        return self._load_receipt_alias(handle, selected)

    def resolve_memory_prestart_closure(self, enrollment: MemoryServiceEnrollment,
                                        handles: tuple[str, ...], *,
                                        service_generation_digest: str) -> RootMemoryPrestartReceipt:
        if (type(enrollment) is not MemoryServiceEnrollment or not handles
                or service_generation_digest != self.bindings.service_generation_digest):
            raise RootMemoryEvidenceDenied("active memory prestart closure selector is invalid")
        matches = []
        for handle in handles:
            try:
                receipt = self.resolve_selected_prestart(handle, enrollment.target_id)
            except RootMemoryEvidenceDenied:
                continue
            if receipt.enclosing_service_generation_digest == service_generation_digest:
                matches.append(receipt)
        matches = list({receipt.receipt_handle: receipt for receipt in matches}.values())
        if len(matches) != 1:
            raise RootMemoryEvidenceDenied("lifecycle handles do not join one retained active prestart receipt")
        receipt = matches[0]
        if tuple(handles) != receipt.runtime_receipt_handles:
            raise RootMemoryEvidenceDenied("lifecycle prestart receipt set differs from retained source closure")
        return receipt


@dataclass(frozen=True, slots=True, repr=False)
class RootMemorySemanticOperationReceipt:
    schema: int
    receipt_handle: str
    route_id: str
    step_id: str
    request_schema_id: str
    result_schema_id: str
    request_sha256: str
    frame_sha256: str
    response_status: int
    response_sha256: str
    validated_result_sha256: str
    process_id: str
    process_identity_digest: str
    service_generation_digest: str
    issued_monotonic: float
    expires_monotonic: float
    _is_current: Callable[[], bool] = field(repr=False, compare=False)

    def is_current(self) -> bool:
        try:
            return time.monotonic() < self.expires_monotonic and self._is_current()
        except Exception:
            return False

    def __repr__(self) -> str:
        return "RootMemorySemanticOperationReceipt(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootMemorySemanticReadinessReceipt:
    schema: int
    receipt_handle: str
    memory_enrollment_id: str
    provider: str
    backend_variant: str
    profile_id: str
    namespace_id: str
    service_enrollment_id: str
    service_generation: str
    enclosing_service_generation_digest: str
    memory_owner_generation: int
    process_identity_digest: str
    prestart_receipt_handle: str
    operation_receipt_handles: tuple[str, ...]
    request_schema_ids: tuple[str, ...]
    result_schema_ids: tuple[str, ...]
    route_id: str
    schema_id: str
    readiness_kind: str
    issued_monotonic: float
    expires_monotonic: float
    _is_current: Callable[[], bool] = field(repr=False, compare=False)

    def is_current(self) -> bool:
        try:
            return self.readiness_kind == "backend-semantic" and time.monotonic() < self.expires_monotonic and self._is_current()
        except Exception:
            return False

    def __repr__(self) -> str:
        return "RootMemorySemanticReadinessReceipt(<root-private>)"


class RootMemorySemanticReadinessRegistry:
    """Run a bounded real search through the selected managed service namespace.

    Health routes remain diagnostic only. Semantic readiness is emitted only
    for exact provider search operations with a reviewed serializer and result
    validator. Providers without both stay unavailable.
    """

    _SEMANTIC_ROUTES = {
        "openviking": ("openviking-find", "find", "openviking-find-owned-v1"),
        "agentmemory": ("agentmemory-search", "search", "agentmemory-search-owned-v1"),
    }

    @classmethod
    def selected_semantic_recipe(cls, enrollment: MemoryServiceEnrollment) -> tuple[str, str, str, Any]:
        """Return one fixed semantic route recipe; never use the configured health route."""
        if type(enrollment) is not MemoryServiceEnrollment:
            raise RootMemoryEvidenceDenied("semantic readiness requires a protected memory enrollment")
        selected = cls._SEMANTIC_ROUTES.get(enrollment.provider)
        if selected is None:
            raise RootMemoryEvidenceDenied("selected memory backend has no reviewed semantic probe")
        route_id, step_id, body_recipe_id = selected
        recipe = enrollment.fixed_route_map.get(route_id)
        if recipe is None or recipe.backend_variant != enrollment.backend_variant:
            raise RootMemoryEvidenceDenied("selected memory search route is not enrolled")
        steps = [item for item in recipe.steps
                 if item.step_id == step_id and item.body_recipe_id == body_recipe_id]
        if len(steps) != 1:
            raise RootMemoryEvidenceDenied("selected memory search serializer is unavailable")
        return route_id, step_id, body_recipe_id, (recipe, steps[0])

    def __init__(self, *, active_bindings: RootRuntimeBindings,
                 managed_process_custody: Any, connector_registry: MemoryNamespaceConnector,
                 root_journal: RootJournalSelection,
                 prestart_registry: RootMemoryPrestartReceiptRegistry,
                 monotonic: Callable[[], float] = time.monotonic,
                 expected_uid: int = 0):
        if (os.geteuid() != expected_uid or expected_uid != 0
                or not isinstance(active_bindings, RootRuntimeBindings)
                or managed_process_custody is not active_bindings.process_manager
                or type(connector_registry) is not MemoryNamespaceConnector
                or root_journal.service_generation_digest != active_bindings.service_generation_digest
                or not isinstance(prestart_registry, RootMemoryPrestartReceiptRegistry)
                or not callable(monotonic)):
            raise RootMemoryEvidenceDenied("root memory readiness bindings are unavailable")
        self.bindings = active_bindings
        self.custody = managed_process_custody
        self.connector = connector_registry
        self.journal = root_journal
        self.prestart = prestart_registry
        self.monotonic = monotonic
        self.expected_uid = expected_uid
        self._receipts: dict[str, RootMemorySemanticReadinessReceipt] = {}
        self._operation_receipts: dict[str, RootMemorySemanticOperationReceipt] = {}
        self._lock = threading.RLock()

    @classmethod
    def from_root_runtime(cls, active_bindings: RootRuntimeBindings,
                          managed_process_custody: Any, connector_registry: MemoryNamespaceConnector,
                          root_journal: RootJournalSelection, *,
                          prestart_registry: RootMemoryPrestartReceiptRegistry,
                          **kwargs: Any) -> "RootMemorySemanticReadinessRegistry":
        return cls(active_bindings=active_bindings,
                   managed_process_custody=managed_process_custody,
                   connector_registry=connector_registry, root_journal=root_journal,
                   prestart_registry=prestart_registry, **kwargs)

    def observe_selected_readiness(self, memory_enrollment_id: str,
                                   owned_process_handle: Any) -> str:
        if os.geteuid() != self.expected_uid:
            raise RootMemoryEvidenceDenied("semantic readiness observation requires root")
        selected = _safe_id(memory_enrollment_id)
        digest = self.bindings.service_generation_digest
        enrollment = self.bindings.resolve_memory_enrollment(selected, service_generation_digest=digest)
        if type(enrollment) is not MemoryServiceEnrollment or enrollment.lifecycle_binding is None:
            raise RootMemoryEvidenceDenied("active memory lifecycle enrollment is unavailable")
        source_handles = enrollment.lifecycle_binding.prestart_receipt_handles
        prestart = self.prestart.resolve_memory_prestart_closure(
            enrollment, source_handles, service_generation_digest=digest)
        if not prestart.is_current():
            raise RootMemoryEvidenceDenied("semantic readiness source closure is stale")
        process_receipt = owned_process_handle
        from hermes_installer.managed_process_custodian import RootSelectedServiceProcessReceipt
        if (type(process_receipt) is not RootSelectedServiceProcessReceipt
                or process_receipt.role != f"memory-{enrollment.provider}"
                or process_receipt.action != "start"
                or process_receipt.enrollment_id != enrollment.service_enrollment_id
                or process_receipt.profile_id != enrollment.profile_id
                or process_receipt.generation != enrollment.service_generation
                or process_receipt.selected_principal_id != enrollment.principal_id
                or process_receipt.selected_namespace_identity != enrollment.namespace_identity
                or process_receipt.service_generation_digest != digest):
            raise RootMemoryEvidenceDenied("managed memory process receipt does not match active selection")
        resolve_process = getattr(self.custody, "resolve_selected_service_process", None)
        if not callable(resolve_process):
            raise RootMemoryEvidenceDenied("managed process identity resolver is unavailable")
        lease = resolve_process(process_receipt)
        if lease is None:
            raise RootMemoryEvidenceDenied("selected memory service process is not live")
        try:
            if (lease.process_id != process_receipt.process_id
                    or lease.profile_id != enrollment.profile_id
                    or lease.generation != enrollment.service_generation
                    or lease.uid != process_receipt.selected_subject_uid
                    or lease.gid != process_receipt.selected_subject_gid
                    or lease.executable_sha256 is None
                    or process_receipt.process_identity_digest != _managed_identity_digest(lease)):
                raise RootMemoryEvidenceDenied("selected memory process identity changed")
            route_id, step_id, _body_recipe_id, selected_recipe = self.selected_semantic_recipe(enrollment)
            recipe, step = selected_recipe
            query = f"hermes-lifecycle-probe-{secrets.token_hex(16)}"
            request = build_memory_request(
                provider=enrollment.provider, route_id=route_id,
                recipe={"credential_reference_id": recipe.credential_reference_id},
                step={"method": step.method, "path_template": step.path_template,
                      "body_recipe_id": step.body_recipe_id},
                body={"query": query, "limit": 1},
                scope_bindings=recipe.scope_bindings,
                maximum_bytes=recipe.maximum_bytes,
            )
            request_sha = _digest(request.body)
            deadline = min(self.monotonic() + min(5.0, recipe.maximum_seconds),
                           prestart.expires_monotonic, process_receipt.expires_monotonic)
            if deadline <= self.monotonic():
                raise RootMemoryEvidenceDenied("semantic readiness lease is exhausted")

            frame_observation: list[str] = []

            def before_connect(frame_sha256: str) -> None:
                if not isinstance(frame_sha256, str) or len(frame_sha256) != 64:
                    raise RootMemoryEvidenceDenied("semantic readiness frame digest is malformed")
                if frame_observation:
                    raise RootMemoryEvidenceDenied("semantic readiness attempted more than one HTTP frame")
                frame_observation.append(frame_sha256)
                fresh = resolve_process(process_receipt)
                if fresh is None:
                    raise RootMemoryEvidenceDenied("selected memory process changed before request bytes")
                try:
                    if (fresh.process_id != lease.process_id or fresh.pid != lease.pid
                            or fresh.start_ticks != lease.start_ticks
                            or fresh.network_namespace_inode != lease.network_namespace_inode
                            or not prestart.is_current()):
                        raise RootMemoryEvidenceDenied("selected memory process or source changed before request")
                finally:
                    fresh.close()

            response = self.connector.request(
                enrollment=enrollment, route_id=route_id, request=request,
                before_connect=before_connect,
                timeout=min(5.0, recipe.maximum_seconds), deadline=deadline,
                cancelled=lambda: self.monotonic() >= deadline,
            )
            if len(frame_observation) != 1:
                raise RootMemoryEvidenceDenied("semantic readiness request did not cross one verified connect boundary")
            try:
                value = json.loads(response.body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise RootMemoryEvidenceDenied("semantic readiness response is not bounded JSON") from None
            outcome = validate_step_outcome(
                route_id=route_id, step_id=step_id, status=response.status,
                value=value, scope_bindings=recipe.scope_bindings,
            )
            result_sha = _digest(_canonical(outcome.result))
            operation_handles = (secrets.token_urlsafe(32),)
            operation_issued = self.monotonic()
            operation_expires = min(operation_issued + 30.0, prestart.expires_monotonic,
                                    process_receipt.expires_monotonic)

            def operation_current() -> bool:
                try:
                    if (self.bindings.service_generation_digest != digest
                            or not prestart.is_current()):
                        return False
                    current_process = resolve_process(process_receipt)
                    if current_process is None:
                        return False
                    try:
                        return (_managed_identity_digest(current_process)
                                == process_receipt.process_identity_digest)
                    finally:
                        current_process.close()
                except Exception:
                    return False

            operation_receipts = (RootMemorySemanticOperationReceipt(
                schema=1, receipt_handle=operation_handles[0], route_id=route_id,
                step_id=step_id, request_schema_id=recipe.request_schema_id,
                result_schema_id=recipe.result_schema_id, request_sha256=request_sha,
                frame_sha256=frame_observation[0], response_status=response.status,
                response_sha256=_digest(response.body),
                validated_result_sha256=result_sha,
                process_id=process_receipt.process_id,
                process_identity_digest=process_receipt.process_identity_digest,
                service_generation_digest=digest, issued_monotonic=operation_issued,
                expires_monotonic=operation_expires, _is_current=operation_current,
            ),)
            with self._lock:
                for operation_receipt in operation_receipts:
                    self._operation_receipts[operation_receipt.receipt_handle] = operation_receipt
        finally:
            lease.close()
        now = self.monotonic()
        handle = secrets.token_urlsafe(32)
        holder: dict[str, RootMemorySemanticReadinessReceipt] = {}

        def current() -> bool:
            try:
                if self.bindings.service_generation_digest != digest or not prestart.is_current():
                    return False
                current_enrollment = self.bindings.resolve_memory_enrollment(
                    selected, service_generation_digest=digest)
                if current_enrollment != enrollment:
                    return False
                if any(not self.resolve_semantic_operation(item).is_current()
                       for item in operation_handles):
                    return False
                fresh = resolve_process(process_receipt)
                if fresh is None:
                    return False
                try:
                    return (fresh.process_id == process_receipt.process_id
                            and fresh.profile_id == enrollment.profile_id
                            and fresh.generation == enrollment.service_generation
                            and _managed_identity_digest(fresh) == process_receipt.process_identity_digest
                            and fresh.network_namespace_inode > 0)
                finally:
                    fresh.close()
            except Exception:
                return False

        receipt = RootMemorySemanticReadinessReceipt(
            schema=1, receipt_handle=handle, memory_enrollment_id=selected,
            provider=enrollment.provider, backend_variant=enrollment.backend_variant,
            profile_id=enrollment.profile_id, namespace_id=enrollment.namespace_identity,
            service_enrollment_id=enrollment.service_enrollment_id,
            service_generation=enrollment.service_generation,
            enclosing_service_generation_digest=digest,
            memory_owner_generation=enrollment.memory_owner_generation,
            process_identity_digest=process_receipt.process_identity_digest,
            prestart_receipt_handle=prestart.receipt_handle,
            operation_receipt_handles=tuple(operation_handles),
            request_schema_ids=(recipe.request_schema_id,),
            result_schema_ids=(recipe.result_schema_id,),
            route_id=route_id, schema_id=recipe.result_schema_id,
            readiness_kind="backend-semantic", issued_monotonic=now,
            expires_monotonic=min(now + 30.0, prestart.expires_monotonic,
                                  process_receipt.expires_monotonic),
            _is_current=current,
        )
        if not receipt.is_current():
            raise RootMemoryEvidenceDenied("semantic readiness evidence changed during observation")
        with self._lock:
            self._receipts[handle] = receipt
        return handle

    def resolve_semantic_operation(self, receipt_handle: str) -> RootMemorySemanticOperationReceipt:
        handle = _safe_id(receipt_handle)
        with self._lock:
            receipt = self._operation_receipts.get(handle)
        if type(receipt) is not RootMemorySemanticOperationReceipt or not receipt.is_current():
            raise RootMemoryEvidenceDenied("semantic operation receipt is absent or stale")
        return receipt

    def resolve_selected_readiness(self, receipt_handle: str,
                                   memory_enrollment_id: str) -> RootMemorySemanticReadinessReceipt:
        handle = _safe_id(receipt_handle)
        selected = _safe_id(memory_enrollment_id)
        with self._lock:
            receipt = self._receipts.get(handle)
        if (type(receipt) is not RootMemorySemanticReadinessReceipt
                or receipt.memory_enrollment_id != selected or not receipt.is_current()):
            raise RootMemoryEvidenceDenied("semantic readiness receipt is absent, foreign, or stale")
        return receipt

    def probe_selected_readiness(self, enrollment: MemoryServiceEnrollment, *,
                                 route_id: str, schema_id: str,
                                 process_receipt: Any, process_identity: Any,
                                 deadline: float) -> RootMemorySemanticReadinessReceipt:
        """Lifecycle-registry adapter; never treats the health route as proof."""
        if (type(enrollment) is not MemoryServiceEnrollment
                or enrollment.lifecycle_binding is None
                or route_id != enrollment.lifecycle_binding.readiness_route_id
                or schema_id != enrollment.lifecycle_binding.readiness_schema_id
                or not math.isfinite(deadline) or deadline <= self.monotonic()
                or getattr(process_identity, "process_id", None)
                    != getattr(process_receipt, "process_id", None)):
            raise RootMemoryEvidenceDenied("selected memory lifecycle readiness selector is stale")
        handle = self.observe_selected_readiness(enrollment.target_id, process_receipt)
        return self.resolve_selected_readiness(handle, enrollment.target_id)
