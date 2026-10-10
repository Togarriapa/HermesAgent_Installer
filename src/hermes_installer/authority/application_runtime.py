"""Root-held source/runtime receipts and selected application dispatch types.

The installer source generation and an isolated environment are separate
claims.  This module gives each claim an independent root-side registry and
keeps the selected workload DTO closed over the active service generation.
No path, command, account, or callback is accepted on a workload request.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from hermes_installer.components.runtime_source import VerifiedComponentGeneration
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.registry.generation import GenerationStore


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}\Z")
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class SelectedApplicationUnavailable(PermissionError):
    """A selected workload lacks current root-verified runtime evidence."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise SelectedApplicationUnavailable(f"selected application {name} digest is malformed")
    return value


def _id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise SelectedApplicationUnavailable(f"selected application {name} is malformed")
    return value


def _secure_generation(store: GenerationStore, identity: str, *, expected_uid: int) -> tuple[Path, Mapping[str, Any], str]:
    """Reopen and independently verify a sealed root generation, including modes."""
    identity = store._id(identity)
    root = store.root / identity
    try:
        root_info = root.lstat()
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != expected_uid
                or stat.S_IMODE(root_info.st_mode) != 0o700):
            raise SelectedApplicationUnavailable("selected source generation is not private root-owned storage")
        actual_root, manifest, manifest_digest = store._verify(identity)
        if actual_root != root or actual_root.is_symlink():
            raise SelectedApplicationUnavailable("selected source generation path changed")
        # `_verify` checks journal ownership and hashes. Re-open every declared
        # file without following links and independently compare inode metadata,
        # owner, mode, digest, and exact file set before issuing a receipt.
        actual_names: set[str] = set()
        for base, dirs, files in os.walk(root, followlinks=False):
            base_path = Path(base)
            for name in dirs:
                child = base_path / name
                info = child.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                        or stat.S_IMODE(info.st_mode) != 0o700):
                    raise SelectedApplicationUnavailable("selected source generation contains an unsafe directory")
            for name in files:
                child = base_path / name
                info = child.lstat()
                if name == "manifest.json" and child == root / "manifest.json":
                    continue
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in {0o400, 0o500, 0o600}):
                    raise SelectedApplicationUnavailable("selected source generation contains an unsafe file")
                relative = child.relative_to(root).as_posix()
                if relative not in manifest["files"]:
                    raise SelectedApplicationUnavailable("selected source generation has an unmanifested file")
                fd = os.open(child, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
                try:
                    opened = os.fstat(fd)
                    if (opened.st_dev != info.st_dev or opened.st_ino != info.st_ino
                            or opened.st_uid != expected_uid or opened.st_nlink != 1):
                        raise SelectedApplicationUnavailable("selected source member changed while opening")
                    digest = hashlib.sha256()
                    with os.fdopen(fd, "rb", closefd=False) as stream:
                        for block in iter(lambda: stream.read(65536), b""):
                            digest.update(block)
                    if digest.hexdigest() != manifest["files"][relative]["sha256"]:
                        raise SelectedApplicationUnavailable("selected source member digest changed")
                finally:
                    os.close(fd)
                actual_names.add(relative)
        if actual_names != set(manifest["files"]):
            raise SelectedApplicationUnavailable("selected source generation manifest is incomplete")
        return root, MappingProxyType(dict(manifest)), manifest_digest
    except SelectedApplicationUnavailable:
        raise
    except Exception as exc:
        raise SelectedApplicationUnavailable("selected source generation failed root verification") from exc


@dataclass(frozen=True, slots=True)
class RootComponentSourceReceipt:
    schema: int
    handle: str
    application_id: str
    source_identity: str
    source_revision: str
    source_tree_sha256: str
    generation_id: str
    generation_manifest_sha256: str
    service_generation_digest: str
    issued_monotonic: float
    expires_monotonic: float
    generation_root: Path
    _manifest: Mapping[str, Any]


class RootComponentSourceReceiptRegistry:
    """Independently reopen root-held generations and issue private source proof."""

    def __init__(self, *, enrollment_catalog: Any, generation_stores: Mapping[str, GenerationStore],
                 expected_uid: int = 0, monotonic: Callable[[], float] = time.monotonic,
                 ttl_seconds: float = 900.0) -> None:
        if (not isinstance(generation_stores, Mapping) or not generation_stores
                or any(not isinstance(key, str) or type(value) is not GenerationStore
                       for key, value in generation_stores.items())
                or type(expected_uid) is not int or expected_uid < 0
                or isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float))
                or not 0 < ttl_seconds <= 3600):
            raise ValueError("root component source receipt registry configuration is invalid")
        self.enrollment_catalog = enrollment_catalog
        self.generation_stores = dict(generation_stores)
        self.expected_uid = expected_uid
        self.monotonic = monotonic
        self.ttl_seconds = float(ttl_seconds)
        self._records: dict[str, RootComponentSourceReceipt] = {}
        self._lock = threading.RLock()

    def _selected(self, application_id: str) -> Mapping[str, Any]:
        resolver = getattr(self.enrollment_catalog, "selected_application_runtime_record", None)
        if not callable(resolver):
            raise SelectedApplicationUnavailable("selected application source row is not enrolled")
        row = resolver(application_id)
        if not isinstance(row, Mapping):
            raise SelectedApplicationUnavailable("selected application source row is unavailable")
        return row

    def record_verified_generation(self, source: VerifiedComponentSource,
                                   generation: VerifiedComponentGeneration, *,
                                   application_id: str) -> str:
        if (type(source) is not VerifiedComponentSource
                or type(generation) is not VerifiedComponentGeneration
                or not isinstance(application_id, str) or not _ID.fullmatch(application_id)):
            raise SelectedApplicationUnavailable("source receipt requires installer-verified source and generation DTOs")
        row = self._selected(application_id)
        store = self.generation_stores.get(application_id)
        if store is None:
            raise SelectedApplicationUnavailable("root-owned source generation store is not configured")
        expected = (
            row.get("application_id") == application_id
            and row.get("source_identity") == source.source_identity == generation.source_identity
            and row.get("source_revision") == source.revision == generation.revision
            and row.get("source_tree_sha256") == source.source_tree_sha == generation.source_tree_sha
            and source.component_id == generation.component_id == application_id
        )
        if not expected:
            raise SelectedApplicationUnavailable("verified source does not match the exact active application pin")
        # Recompute the source contract without calling the staging adapter:
        # that adapter may create or repair a generation and is required to
        # run under the installer mutation lock. Receipt issuance is read-only.
        try:
            from hermes_installer.components.runtime_source import (
                _git_tree, resolve_component_adapter,
            )
            contract = resolve_component_adapter(application_id)
            upstream = {name: body for name, body in source.files.items()
                        if name != "INSTALLER-SOURCE-PROVENANCE.json"}
            modes = {name: source.file_modes[name] for name in upstream}
            tree_sha, _ = _git_tree(upstream, modes)
            provenance = json.loads(source.files["INSTALLER-SOURCE-PROVENANCE.json"].decode("utf-8"))
            expected_provenance = {
                "schema": 1, "component_id": application_id,
                "source_identity": source.source_identity,
                "source_url": contract.selected_source_url,
                "revision": source.revision,
                "source_selection": contract.source_selection,
                "source_archive_sha256": source.archive_sha256,
                "source_content_sha256": source.content_sha256,
                "source_tree_sha": source.source_tree_sha,
                "declared_license": contract.license,
                "license_files": list(source.license_files),
                "redistribution_license_review_required": contract.redistribution_license_review_required,
            }
            compiled_files, compiled_modes = source.compiled_files()
            expected_files = {
                name: {"sha256": hashlib.sha256(body).hexdigest(),
                       "mode": store._private_mode(compiled_modes[name])}
                for name, body in compiled_files.items()
            }
        except Exception as exc:
            raise SelectedApplicationUnavailable("verified source bundle failed independent pin validation") from exc
        if (tree_sha != source.source_tree_sha or provenance != expected_provenance
                or source.license != contract.license
                or source.redistribution_license_review_required != contract.redistribution_license_review_required):
            raise SelectedApplicationUnavailable("verified source bundle differs from its pinned provenance")
        root, manifest, digest = _secure_generation(store, source.generation_id, expected_uid=self.expected_uid)
        service_digest = getattr(self.enrollment_catalog, "generation_digest", None)
        if (not isinstance(service_digest, str) or not _SHA.fullmatch(service_digest)
                or manifest.get("generation") != source.generation_id
                or manifest.get("files") != expected_files
                or generation.generation_digest != digest or generation.root != root
                or generation.source_tree_sha != source.source_tree_sha
                or row.get("source_generation_manifest_sha256") != digest):
            raise SelectedApplicationUnavailable("verified source generation does not match the active receipt row")
        now = self.monotonic()
        # Receipt identities are chosen by the authenticated active snapshot,
        # avoiding recursive embedding of the enclosing generation digest.
        handle = row.get("source_generation_receipt_handle")
        if not isinstance(handle, str) or not _OPAQUE.fullmatch(handle):
            raise SelectedApplicationUnavailable("active source receipt handle is missing or malformed")
        receipt = RootComponentSourceReceipt(
            1, handle, application_id, source.source_identity, source.revision,
            source.source_tree_sha, source.generation_id, digest, service_digest,
            now, now + self.ttl_seconds, root, manifest,
        )
        with self._lock:
            if len(self._records) >= 100_000:
                raise SelectedApplicationUnavailable("root source receipt registry is full")
            self._records[handle] = receipt
        return handle

    def resolve(self, handle: str, *, application_id: str,
                service_generation_digest: str) -> RootComponentSourceReceipt:
        if not isinstance(handle, str) or not _OPAQUE.fullmatch(handle):
            raise SelectedApplicationUnavailable("source receipt handle is malformed")
        with self._lock:
            receipt = self._records.get(handle)
        if (receipt is None or receipt.handle != handle or receipt.application_id != application_id
                or receipt.service_generation_digest != service_generation_digest
                or self.monotonic() >= receipt.expires_monotonic):
            raise SelectedApplicationUnavailable("source receipt is absent, expired, or stale")
        store = self.generation_stores.get(application_id)
        if store is None:
            raise SelectedApplicationUnavailable("root source generation store is unavailable")
        root, manifest, digest = _secure_generation(store, receipt.generation_id, expected_uid=self.expected_uid)
        if root != receipt.generation_root or digest != receipt.generation_manifest_sha256 or manifest != receipt._manifest:
            raise SelectedApplicationUnavailable("source receipt no longer matches its held generation")
        if getattr(self.enrollment_catalog, "generation_digest", None) != service_generation_digest:
            raise SelectedApplicationUnavailable("source receipt belongs to a stale service generation")
        return receipt


@dataclass(frozen=True, slots=True)
class ManagedApplicationRuntimeProbe:
    """Root-only terminal probe facts returned by process-custody lookup."""
    receipt_handle: str
    runtime_id: str
    runtime_manifest_sha256: str
    lock_sha256: str
    python_version: str
    SOABI: str
    machine: str
    platform: str
    dependency_artifact_ids: tuple[str, ...]
    terminal_success: bool
    service_generation_digest: str
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class RootApplicationRuntimeReceipt:
    schema: int
    handle: str
    application_id: str
    source_receipt_handle: str
    runtime_id: str
    runtime_manifest_sha256: str
    lock_sha256: str
    python_version: str
    SOABI: str
    machine: str
    platform: str
    dependency_artifact_ids: tuple[str, ...]
    probe_receipt_handle: str
    service_generation_digest: str
    issued_monotonic: float
    expires_monotonic: float
    runtime_root: Path
    _manifest: Mapping[str, Any]


class RootApplicationRuntimeReceiptRegistry:
    """Bind an immutable isolated environment to a root-observed managed probe."""

    def __init__(self, *, source_receipts: RootComponentSourceReceiptRegistry,
                 enrollment_catalog: Any, runtime_stores: Mapping[str, GenerationStore],
                 managed_probe_registry: "RootManagedApplicationRuntimeProbeRegistry",
                 expected_uid: int = 0, monotonic: Callable[[], float] = time.monotonic,
                 ttl_seconds: float = 900.0) -> None:
        if (type(source_receipts) is not RootComponentSourceReceiptRegistry
                or not isinstance(runtime_stores, Mapping) or not runtime_stores
                or type(managed_probe_registry) is not RootManagedApplicationRuntimeProbeRegistry
                or any(not isinstance(key, str) or type(value) is not GenerationStore
                       for key, value in runtime_stores.items())
                or type(expected_uid) is not int or expected_uid < 0
                or isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float))
                or not 0 < ttl_seconds <= 3600):
            raise ValueError("root application runtime receipt registry configuration is invalid")
        self.source_receipts = source_receipts
        self.enrollment_catalog = enrollment_catalog
        self.runtime_stores = dict(runtime_stores)
        self.managed_probe_registry = managed_probe_registry
        self.expected_uid = expected_uid
        self.monotonic = monotonic
        self.ttl_seconds = float(ttl_seconds)
        self._records: dict[str, RootApplicationRuntimeReceipt] = {}
        self._lock = threading.RLock()

    def record_observed_environment(self, source_receipt_handle: str,
                                    selected_locked_runtime: Mapping[str, Any],
                                    managed_probe_receipt_handle: str) -> str:
        if not isinstance(selected_locked_runtime, Mapping):
            raise SelectedApplicationUnavailable("runtime receipt requires a selected locked runtime")
        application_id = _id(selected_locked_runtime.get("application_id"), "application ID")
        service_digest = getattr(self.enrollment_catalog, "generation_digest", None)
        source = self.source_receipts.resolve(
            source_receipt_handle, application_id=application_id,
            service_generation_digest=service_digest,
        )
        runtime_id = _id(selected_locked_runtime.get("runtime_id"), "runtime ID")
        # Probe facts are never accepted from the app, caller, or this API's
        # argument object. Only the root process-custody registry may resolve
        # a terminal observation it issued for the selected runtime.
        actual_managed_probe = self.managed_probe_registry.resolve(
            managed_probe_receipt_handle, application_id=application_id,
            runtime_id=runtime_id, service_generation_digest=service_digest,
        )
        if type(actual_managed_probe) is not ManagedApplicationRuntimeProbe:
            raise SelectedApplicationUnavailable("root custody returned no typed runtime probe receipt")
        store = self.runtime_stores.get(runtime_id)
        if store is None:
            raise SelectedApplicationUnavailable("selected isolated runtime generation is unavailable")
        lock_sha = _digest(selected_locked_runtime.get("lock_sha256"), "lock")
        if (actual_managed_probe.runtime_id != runtime_id
                or actual_managed_probe.lock_sha256 != lock_sha
                or actual_managed_probe.service_generation_digest != service_digest
                or actual_managed_probe.expires_monotonic <= self.monotonic()
                or not isinstance(actual_managed_probe.receipt_handle, str)
                or not _OPAQUE.fullmatch(actual_managed_probe.receipt_handle)):
            raise SelectedApplicationUnavailable("managed runtime probe does not match the current locked selection")
        root, manifest, digest = _secure_generation(
            store, runtime_id, expected_uid=self.expected_uid,
        )
        if (digest != actual_managed_probe.runtime_manifest_sha256
                or selected_locked_runtime.get("runtime_manifest_sha256") != digest
                or not actual_managed_probe.python_version or not actual_managed_probe.SOABI
                or actual_managed_probe.machine not in {"aarch64", "arm64"}
                or not actual_managed_probe.platform.startswith("linux")
                or not actual_managed_probe.dependency_artifact_ids
                or len(actual_managed_probe.dependency_artifact_ids) > 256
                or len(set(actual_managed_probe.dependency_artifact_ids)) != len(actual_managed_probe.dependency_artifact_ids)):
            raise SelectedApplicationUnavailable("isolated environment manifest or observed ARM64 ABI is not qualified")
        row = self.enrollment_catalog.selected_application_runtime_record(application_id)
        receipt_handle = row.get("runtime_receipt_handle")
        if not isinstance(receipt_handle, str) or not _OPAQUE.fullmatch(receipt_handle):
            raise SelectedApplicationUnavailable("active runtime receipt handle is missing or malformed")
        if (row.get("source_generation_receipt_handle") != source.handle
                or row.get("runtime_id") != runtime_id
                or row.get("runtime_manifest_sha256") != digest
                or row.get("lock_sha256") != lock_sha):
            raise SelectedApplicationUnavailable("observed isolated runtime does not match selected active receipt row")
        now = self.monotonic()
        handle = receipt_handle
        receipt = RootApplicationRuntimeReceipt(
            1, handle, application_id, source_receipt_handle, runtime_id, digest,
            lock_sha, actual_managed_probe.python_version, actual_managed_probe.SOABI,
            actual_managed_probe.machine, actual_managed_probe.platform,
            tuple(actual_managed_probe.dependency_artifact_ids),
            actual_managed_probe.receipt_handle, service_digest,
            now, min(now + self.ttl_seconds, actual_managed_probe.expires_monotonic),
            root, manifest,
        )
        with self._lock:
            if len(self._records) >= 100_000:
                raise SelectedApplicationUnavailable("root application runtime receipt registry is full")
            self._records[handle] = receipt
        return handle

    def resolve(self, handle: str, *, application_id: str,
                source_receipt_handle: str, service_generation_digest: str) -> RootApplicationRuntimeReceipt:
        if not isinstance(handle, str) or not _OPAQUE.fullmatch(handle):
            raise SelectedApplicationUnavailable("runtime receipt handle is malformed")
        with self._lock:
            receipt = self._records.get(handle)
        if (receipt is None or receipt.application_id != application_id
                or receipt.source_receipt_handle != source_receipt_handle
                or receipt.service_generation_digest != service_generation_digest
                or self.monotonic() >= receipt.expires_monotonic):
            raise SelectedApplicationUnavailable("runtime receipt is absent, expired, or stale")
        source = self.source_receipts.resolve(
            source_receipt_handle, application_id=application_id,
            service_generation_digest=service_generation_digest,
        )
        store = self.runtime_stores.get(receipt.runtime_id)
        if store is None:
            raise SelectedApplicationUnavailable("selected runtime store is unavailable")
        root, manifest, digest = _secure_generation(store, receipt.runtime_id, expected_uid=self.expected_uid)
        if (root != receipt.runtime_root or digest != receipt.runtime_manifest_sha256
                or manifest != receipt._manifest or source.handle != receipt.source_receipt_handle
                or getattr(self.enrollment_catalog, "generation_digest", None) != service_generation_digest):
            raise SelectedApplicationUnavailable("runtime receipt no longer matches its root-held environment")
        return receipt


class RootManagedApplicationRuntimeProbeRegistry:
    """Resolve terminal runtime probes held by the actual root process manager.

    The process manager must implement the narrow resolver that joins its own
    retained start and terminal receipt objects. No callable is supplied by an
    installer worker or selected application.
    """

    def __init__(self, process_manager: Any, *, monotonic: Callable[[], float] = time.monotonic) -> None:
        from hermes_installer.managed_process_custodian import ManagedProcessEffectHandler
        if type(process_manager) is not ManagedProcessEffectHandler:
            raise ValueError("application runtime probe registry requires the concrete root process manager")
        self.process_manager = process_manager
        self.monotonic = monotonic

    def resolve(self, receipt_handle: str, *, application_id: str, runtime_id: str,
                service_generation_digest: str) -> ManagedApplicationRuntimeProbe:
        if not isinstance(receipt_handle, str) or not _OPAQUE.fullmatch(receipt_handle):
            raise SelectedApplicationUnavailable("managed runtime probe handle is malformed")
        resolver = getattr(self.process_manager, "resolve_application_runtime_probe", None)
        if not callable(resolver):
            raise SelectedApplicationUnavailable(
                "managed process custody has no selected isolated-runtime probe receipt producer"
            )
        try:
            probe = resolver(receipt_handle)
        except Exception:
            raise SelectedApplicationUnavailable("root managed runtime probe is unavailable or stale") from None
        if (type(probe) is not ManagedApplicationRuntimeProbe
                or probe.receipt_handle != receipt_handle or probe.runtime_id != runtime_id
                or probe.service_generation_digest != service_generation_digest
                or probe.expires_monotonic <= self.monotonic()):
            raise SelectedApplicationUnavailable("managed runtime probe does not match the selected application")
        return probe


@dataclass(frozen=True, slots=True)
class RootSelectedApplicationRuntime:
    """Closed selected row joined to current root source/runtime receipts."""
    application_id: str
    profile_id: str
    profile_generation: str
    principal_id: str
    adapter_id: str
    source_identity: str
    source_revision: str
    source_tree_sha256: str
    source_generation_receipt_handle: str
    source_generation_manifest_sha256: str
    runtime_id: str
    runtime_receipt_handle: str
    runtime_manifest_sha256: str
    lock_sha256: str
    work_root_id: str
    data_root_id: str
    operation_id: str
    process_start_target: str
    request_schema_id: str
    request_schema_sha256: str
    result_schema_id: str
    result_validator_artifact_id: str
    result_validator_sha256: str
    capability_ids: tuple[str, ...]
    provider_route_ids: tuple[str, ...]
    credential_reference_ids: tuple[str, ...]
    account_eligibility_receipt_handle: str | None
    memory_owner_generation: int | None
    max_lifetime_seconds: int
    max_memory_bytes: int
    max_workers: int
    metered_budget_usd: str
    enabled: bool
    service_generation_digest: str
    source_receipt: RootComponentSourceReceipt
    runtime_receipt: RootApplicationRuntimeReceipt
    request_schema: Any


@dataclass(frozen=True, slots=True)
class RootApplicationRunReceipt:
    schema: int
    receipt_handle: str
    application_id: str
    profile_id: str
    profile_generation: str
    service_generation_digest: str
    source_receipt_handle: str
    runtime_receipt_handle: str
    operation_id: str
    request_sha256: str
    terminal_receipt_handle: str
    result_capsule_handle: str
    state: str
    issued_monotonic: float
    expires_monotonic: float

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": self.schema, "receipt_handle": self.receipt_handle,
            "application_id": self.application_id, "profile_id": self.profile_id,
            "profile_generation": self.profile_generation,
            "service_generation_digest": self.service_generation_digest,
            "source_receipt_handle": self.source_receipt_handle,
            "runtime_receipt_handle": self.runtime_receipt_handle,
            "operation_id": self.operation_id, "request_sha256": self.request_sha256,
            "terminal_receipt_handle": self.terminal_receipt_handle,
            "result_capsule_handle": self.result_capsule_handle,
            "state": self.state, "issued_monotonic": self.issued_monotonic,
            "expires_monotonic": self.expires_monotonic,
        }


class RootSelectedApplicationRuntimeRouter:
    """Root-only resolver and dispatcher for one active selected app row.

    The constructor deliberately requires a typed selected-invocation resolver.
    The current native observer does not expose selected adapter/action plus its
    authenticated parent context, so composition must remain disabled until a
    concrete root registry supplies that proof.
    """

    def __init__(self, *, service: Any, bindings: Any,
                 source_receipts: RootComponentSourceReceiptRegistry,
                 runtime_receipts: RootApplicationRuntimeReceiptRegistry,
                 selected_invocation_resolver: Any,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        if (not callable(getattr(service, "_binding", None))
                or not callable(getattr(bindings, "resolve_selected_application_runtime", None))
                or type(source_receipts) is not RootComponentSourceReceiptRegistry
                or type(runtime_receipts) is not RootApplicationRuntimeReceiptRegistry
                or not callable(getattr(selected_invocation_resolver, "resolve_selected_application_invocation", None))):
            raise ValueError("selected application router requires all concrete root receipt and invocation resolvers")
        self.service = service
        self.bindings = bindings
        self.source_receipts = source_receipts
        self.runtime_receipts = runtime_receipts
        self.selected_invocation_resolver = selected_invocation_resolver
        self.monotonic = monotonic
        self._runs: dict[str, RootApplicationRunReceipt] = {}
        self._lock = threading.RLock()

    def resolve(self, application_id: str, profile_id: str) -> RootSelectedApplicationRuntime:
        """Resolve a current row; never fall back to fixture or caller paths."""
        selection = self.bindings.resolve_selected_application_runtime(application_id, profile_id)
        if type(selection) is not RootSelectedApplicationRuntime:
            raise SelectedApplicationUnavailable("root binding returned an untyped selected application")
        if (selection.service_generation_digest != getattr(self.bindings.enrollment_catalog, "digest", None)
                or selection.enabled is not True or selection.max_workers != 1
                or selection.metered_budget_usd != "0"):
            raise SelectedApplicationUnavailable("selected application is disabled, stale, or exceeds default limits")
        source = self.source_receipts.resolve(
            selection.source_generation_receipt_handle,
            application_id=application_id,
            service_generation_digest=selection.service_generation_digest,
        )
        runtime = self.runtime_receipts.resolve(
            selection.runtime_receipt_handle,
            application_id=application_id,
            source_receipt_handle=source.handle,
            service_generation_digest=selection.service_generation_digest,
        )
        if (source.source_identity != selection.source_identity
                or source.source_revision != selection.source_revision
                or source.source_tree_sha256 != selection.source_tree_sha256
                or source.generation_manifest_sha256 != selection.source_generation_manifest_sha256
                or runtime.runtime_id != selection.runtime_id
                or runtime.runtime_manifest_sha256 != selection.runtime_manifest_sha256
                or runtime.lock_sha256 != selection.lock_sha256):
            raise SelectedApplicationUnavailable("selected source/runtime receipts do not match the active row")
        return selection

    def dispatch(self, invocation_context_handle: str, application_id: str,
                 canonical_arguments: bytes, *, peer_uid: int, peer_pid: int,
                 peer_pidfd: int | None, cancelled: Callable[[], bool]) -> RootApplicationRunReceipt:
        """Dispatch only after the root invocation resolver binds the exact call."""
        if (not isinstance(invocation_context_handle, str) or not _OPAQUE.fullmatch(invocation_context_handle)
                or not isinstance(application_id, str) or not _ID.fullmatch(application_id)
                or not isinstance(canonical_arguments, bytes) or not 1 <= len(canonical_arguments) <= 2 * 1024 * 1024
                or type(peer_uid) is not int or peer_uid <= 0 or type(peer_pid) is not int or peer_pid <= 0
                or peer_pidfd is None or type(peer_pidfd) is not int or peer_pidfd < 0
                or not callable(cancelled) or cancelled()):
            raise SelectedApplicationUnavailable("selected application invocation is malformed or cancelled")
        invocation = self.selected_invocation_resolver.resolve_selected_application_invocation(
            invocation_context_handle, peer_uid=peer_uid, peer_pid=peer_pid,
            peer_pidfd=peer_pidfd, canonical_arguments=canonical_arguments,
        )
        if (getattr(invocation, "application_id", None) != application_id
                or getattr(invocation, "arguments_sha256", None) != hashlib.sha256(canonical_arguments).hexdigest()
                or getattr(invocation, "expires_monotonic", 0) <= self.monotonic()):
            raise SelectedApplicationUnavailable("root invocation does not bind this exact selected application request")
        # The exact grant/process operation is installed by the AuthorityService
        # seam against this typed resolver. Until that one-use helper is present,
        # fail closed instead of emitting a synthetic success receipt.
        raise SelectedApplicationUnavailable(
            "selected application process-start/result capsule adapter is not yet attached to root composition"
        )
