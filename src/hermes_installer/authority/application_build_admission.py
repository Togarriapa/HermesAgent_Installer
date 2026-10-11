"""Finite root-owned setup admission for selected application environment builds.

This module is deliberately separate from the worker build-job API.  It joins
the retained v132 preparation selection to the source, package/backend,
toolchain, installed driver, setup service and output-root receipts before a
one-use setup-only grant can be issued.  A missing reviewed input remains a
typed denial; callers cannot provide paths, argv, targets or package facts.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import posixpath
import secrets
import stat
import time
import threading
import urllib.parse
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping


_SELECTION_SEAL = object()
_GRANT_SEAL = object()
_INPUTS_SEAL = object()
_APP_BUILD_PROFILES: Mapping[str, tuple[str, str, str, str]] = MappingProxyType({
    "graphify": ("qualify-graphify-v1", "python",
                 "application-graphify-runtime-prepare-v1",
                 "application-graphify-runtime-prepare:start"),
    "browser-use": ("qualify-browser-use-v1", "python",
                    "application-browser-use-runtime-prepare-v1",
                    "application-browser-use-runtime-prepare:start"),
    "hyperframes": ("qualify-hyperframes-v1", "node",
                    "application-hyperframes-runtime-prepare-v1",
                    "application-hyperframes-runtime-prepare:start"),
    "scrapegraph-ai": ("qualify-scrapegraph-v1", "python",
                       "application-scrapegraph-ai-runtime-prepare-v1",
                       "application-scrapegraph-ai-runtime-prepare:start"),
})
_DRIVER_ARTIFACT_ID = "installer-application-environment-builder-v1"
_DRIVER_MEMBER_PATH = "lib/python/hermes_installer/authority/application_environment_builder.py"
_MAX_RUNTIME_ARCHIVE_BYTES = 2_147_483_648
_MAX_LIFETIME_SECONDS = 600


class ApplicationBuildAdmissionDenied(PermissionError):
    """A selected application build lacks current finite root-held inputs."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _opaque(value: Any, label: str) -> str:
    if (not isinstance(value, str) or not 32 <= len(value) <= 128
            or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                   for char in value)):
        raise ApplicationBuildAdmissionDenied(f"{label} handle is malformed")
    return value


def _digest(value: Any, label: str) -> str:
    if (not isinstance(value, str) or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise ApplicationBuildAdmissionDenied(f"{label} digest is malformed")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationBuildInputMember:
    """A materialized input file whose bytes are held by a sealed descriptor."""

    relative_path: str
    fd: int
    sha256: str
    size_bytes: int
    executable: bool
    receipt_handle: str
    kind: str = "file"
    link_target: str | None = None
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _INPUTS_SEAL:
            raise TypeError("application build members are issued by the root admission")

    @classmethod
    def _mint(cls, **claims: Any) -> "RootApplicationBuildInputMember":
        claims.pop("_seal", None)
        return cls(**claims, _seal=_INPUTS_SEAL)


@dataclass(frozen=True, slots=True, repr=False)
class RootResolvedApplicationBuildInputs:
    """Descriptor-backed private inputs handed only to the managed root runner.

    Every descriptor in this object is a duplicate owned by this instance.
    The managed runner must call ``close()`` after it has staged or rejected
    the request.  No host filesystem path is present in the public API.
    """

    selection_handle: str
    application_id: str
    build_profile_id: str
    target_id: str
    operation_id: str
    runtime_preparation_selection_handle: str
    plan_sha256: str
    setup_session_id: str
    transaction_handle: str
    prepared_generation_id: str
    prepared_generation_digest: str
    source_receipt_handle: str
    source_manifest_sha256: str
    pm_runtime_closure_sha256: str
    lock_receipt_handle: str
    lock_sha256: str
    package_closure_receipt_handle: str
    build_backend_closure_receipt_handle: str | None
    recipe_sha256: str
    builder_fd: int
    builder_receipt_handle: str
    builder_sha256: str
    builder_size_bytes: int
    python_executable_member: RootApplicationBuildInputMember
    source_members: tuple[RootApplicationBuildInputMember, ...]
    package_members: tuple[RootApplicationBuildInputMember, ...]
    backend_members: tuple[RootApplicationBuildInputMember, ...]
    python_runtime_members: tuple[RootApplicationBuildInputMember, ...]
    uv_fd: int | None
    uv_sha256: str | None
    uv_size_bytes: int | None
    uv_source_receipt_handle: str
    uv_artifact_id: str
    driver_fd: int
    driver_receipt_handle: str
    driver_sha256: str
    driver_size_bytes: int
    recipe_config_bytes: bytes
    recipe_config_sha256: str
    recipe_member: RootApplicationBuildInputMember
    output_root_fd: int
    output_root_id: str
    output_owner_uid: int
    output_owner_gid: int
    build_service_id: str
    build_service_selection_handle: str
    build_service_generation: str
    runtime_toolchain_receipt_handles: tuple[str, ...]
    controller_binding_handle: str
    controller_pidfd: int
    controller_pid: int
    controller_start_ticks: int
    controller_uid: int
    controller_gid: int
    _registry: Any = field(repr=False, compare=False)
    _selection: Any = field(repr=False, compare=False)
    _owned_fds: tuple[int, ...] = field(repr=False, compare=False)
    _close_lock: Any = field(default_factory=threading.Lock, init=False, repr=False, compare=False)
    _closed: bool = field(default=False, init=False, repr=False, compare=False)
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _INPUTS_SEAL:
            raise TypeError("resolved application build inputs are issued by the root admission")

    def verify_current(self) -> "RootResolvedApplicationBuildInputs":
        """Revalidate the originating selection and return fresh owned descriptors."""
        return self._registry.verify_current(self._selection)

    def close(self) -> None:
        """Close all duplicates, idempotently."""
        with self._close_lock:
            if self._closed:
                return
            object.__setattr__(self, "_closed", True)
            for fd in self._owned_fds:
                try:
                    os.close(fd)
                except OSError:
                    pass


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedApplicationBuildSelection:
    schema: int
    selection_handle: str
    runtime_preparation_selection_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    application_id: str
    workflow_id: str
    build_profile_id: str
    operation_id: str
    target_id: str
    build_service_selection_handle: str
    build_service_enrollment_id: str
    build_service_generation: str
    source_receipt_handle: str
    source_manifest_sha256: str
    pm_runtime_closure_sha256: str
    lock_receipt_handle: str
    lock_sha256: str
    package_closure_receipt_handle: str
    build_backend_closure_receipt_handle: str | None
    runtime_toolchain_receipt_handles: tuple[str, ...]
    builder_module_receipt_handle: str
    builder_module_sha256: str
    recipe_sha256: str
    output_root_receipt_handle: str
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    source: Any = field(repr=False, compare=False)
    lock: Any = field(repr=False, compare=False)
    package_closure: Any = field(repr=False, compare=False)
    backend_closure: Any = field(repr=False, compare=False)
    runtime_toolchains: tuple[Any, ...] = field(repr=False, compare=False)
    builder_module: Any = field(repr=False, compare=False)
    pm_runtime: Any = field(repr=False, compare=False)
    pm_projection: Any = field(repr=False, compare=False)
    pm_uv: Any = field(repr=False, compare=False)
    build_service: Any = field(repr=False, compare=False)
    build_profile: Any = field(repr=False, compare=False)
    output_root: Any = field(repr=False, compare=False)
    _registry: Any = field(repr=False, compare=False)
    _producer_id: str = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SELECTION_SEAL:
            raise TypeError("application build selections are issued only by the root admission")

    def verify_current(self) -> RootResolvedApplicationBuildInputs:
        """Re-resolve every root-held join and return fresh owned descriptors."""
        return self._registry.verify_current(self)


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationSetupBuildGrant:
    """One-use setup-only build admission; it is not a worker effect grant."""

    grant_id: str
    selection_handle: str
    runtime_preparation_selection_handle: str
    setup_session_id: str
    transaction_handle: str
    prepared_generation_id: str
    prepared_generation_digest: str
    build_service_id: str
    build_service_generation: str
    target: str
    operation_id: str
    parameters_digest: str
    recipe_sha256: str
    controller_binding_handle: str
    expires_monotonic: float
    _issuer_id: str = field(repr=False, compare=False)
    _signature: str = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _GRANT_SEAL:
            raise TypeError("application setup build grants are issued by the root setup authority")


class RootApplicationBuildAdmissionRegistry:
    """Select and continuously revalidate one fixed application setup build."""

    def __init__(self, *, selected_installation_binding: Any,
                 runtime_preparation_selection_registry: Any,
                 source_preparation_registry: Any, backend_closure_registry: Any,
                 toolchain_registry: Any, package_closure_registry: Any,
                 root_journal: Any, monotonic=time.monotonic,
                 ttl_seconds: float = 300.0):
        from ..protected_enrollment import RootJournalSelection
        if (os.geteuid() != 0 or type(root_journal) is not RootJournalSelection
                or not callable(getattr(selected_installation_binding,
                                        "resolve_application_runtime_preparation_selection", None))
                or not callable(getattr(selected_installation_binding,
                                        "resolve_prepared_application_build_service", None))
                or not callable(getattr(runtime_preparation_selection_registry,
                                        "resolve_application_runtime_preparation_selection", None))
                or not callable(getattr(source_preparation_registry,
                                        "resolve_current_prepared_source_for_selection", None))
                or not callable(getattr(source_preparation_registry,
                                        "resolve_current_lock_for_selection", None))
                or not callable(getattr(package_closure_registry,
                                        "resolve_current_package_closure_for_selection", None))
                or not callable(getattr(backend_closure_registry,
                                        "resolve_current_backend_closure_for_selection", None))
                or not 0 < ttl_seconds <= 300):
            raise ApplicationBuildAdmissionDenied("root application build admission inputs are unavailable")
        self.binding = selected_installation_binding
        self.runtime_registry = runtime_preparation_selection_registry
        self.source_registry = source_preparation_registry
        self.backend_registry = backend_closure_registry
        self.toolchain_registry = toolchain_registry
        self.package_registry = package_closure_registry
        self.root_journal = root_journal
        self.monotonic = monotonic
        self.ttl_seconds = float(ttl_seconds)
        self.producer_id = secrets.token_urlsafe(24)
        self._selections: dict[str, RootSelectedApplicationBuildSelection] = {}
        self._by_preparation: dict[str, str] = {}

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        runtime_preparation_selection_registry: Any,
                        source_preparation_registry: Any,
                        backend_closure_registry: Any,
                        toolchain_registry: Any, package_closure_registry: Any,
                        root_journal: Any, **kwargs: Any) -> "RootApplicationBuildAdmissionRegistry":
        return cls(
            selected_installation_binding=selected_installation_binding,
            runtime_preparation_selection_registry=runtime_preparation_selection_registry,
            source_preparation_registry=source_preparation_registry,
            backend_closure_registry=backend_closure_registry,
            toolchain_registry=toolchain_registry,
            package_closure_registry=package_closure_registry,
            root_journal=root_journal, **kwargs)

    def select_current_application_build(
            self, runtime_preparation_selection_handle: str
            ) -> RootSelectedApplicationBuildSelection:
        _opaque(runtime_preparation_selection_handle, "runtime preparation selection")
        prior_handle = self._by_preparation.get(runtime_preparation_selection_handle)
        if prior_handle is not None:
            retained = self._selections[prior_handle]
            current = self.verify_current(retained)
            current.close()
            return retained
        facts = self._current_facts(runtime_preparation_selection_handle, create_output=True)
        try:
            selection = facts["selection"]
            service = facts["service"]
            output = facts["output"]
            profile = facts["profile"]
            now = self.monotonic()
            expires = min(now + self.ttl_seconds, selection.expires_monotonic,
                          facts["prep"].expires_monotonic, facts["package"].expires_monotonic,
                          facts["backend"].expires_monotonic if facts["backend"] is not None
                          else selection.expires_monotonic,
                          service.expires_monotonic,
                          facts["source"].expires_monotonic,
                          facts["lock"].expires_monotonic,
                          facts["driver"].expires_monotonic
                          if hasattr(facts["driver"], "expires_monotonic")
                          else service.expires_monotonic)
            if expires <= now:
                raise ApplicationBuildAdmissionDenied("application build inputs expired before admission")
            recipe = self._recipe_digest(facts)
            handle = secrets.token_urlsafe(36)
            build = facts["build"]
            result = RootSelectedApplicationBuildSelection(
                schema=1, selection_handle=handle,
                runtime_preparation_selection_handle=runtime_preparation_selection_handle,
                setup_session_id=selection.setup_session_id,
                transaction_handle=selection.transaction_handle,
                plan_sha256=selection.plan_sha256,
                prepared_generation_id=selection.prepared_generation_id,
                prepared_generation_digest=selection.prepared_generation_digest,
                application_id=selection.application_id,
                workflow_id=selection.workflow_id,
                build_profile_id=selection.build_profile_id,
                operation_id=selection.operation_id, target_id=selection.target_id,
                build_service_selection_handle=service.service_selection_handle,
                build_service_enrollment_id=service.id,
                build_service_generation=service.generation,
                source_receipt_handle=facts["source"].receipt_handle,
                source_manifest_sha256=facts["source"].source_generation_manifest_sha256,
                pm_runtime_closure_sha256=facts["pm_projection"].base_closure_sha256,
                lock_receipt_handle=facts["lock"].receipt_handle,
                lock_sha256=facts["lock"].lock_sha256,
                package_closure_receipt_handle=facts["package"].receipt_handle,
                build_backend_closure_receipt_handle=(facts["backend"].receipt_handle
                                                       if facts["backend"] is not None else None),
                runtime_toolchain_receipt_handles=tuple(selection.runtime_toolchain_receipt_handles),
                builder_module_receipt_handle=facts["driver"].receipt_handle,
                builder_module_sha256=facts["driver"].sha256,
                recipe_sha256=recipe,
                output_root_receipt_handle=output.output_root_id,
                controller_binding_handle=selection.controller_binding_handle,
                issued_monotonic=now, expires_monotonic=expires,
                source=facts["source"], lock=facts["lock"],
                package_closure=facts["package"], backend_closure=facts["backend"],
                runtime_toolchains=tuple(facts["toolchains"]), builder_module=facts["driver"],
                pm_runtime=facts["pm_runtime"], pm_projection=facts["pm_projection"],
                pm_uv=facts["pm_uv"],
                build_service=service, build_profile=profile, output_root=output,
                _registry=self, _producer_id=self.producer_id, _seal=_SELECTION_SEAL)
            self._selections[handle] = result
            self._by_preparation[runtime_preparation_selection_handle] = handle
            return result
        finally:
            # Selection retains typed root registries and output capability, not
            # temporary duplicated input descriptors returned to the caller.
            self._close_fact_fds(facts)

    def verify_current(self, selection: RootSelectedApplicationBuildSelection
                       ) -> RootResolvedApplicationBuildInputs:
        if (type(selection) is not RootSelectedApplicationBuildSelection
                or selection._seal is not _SELECTION_SEAL
                or selection._registry is not self
                or selection._producer_id != self.producer_id
                or self._selections.get(selection.selection_handle) is not selection
                or selection.expires_monotonic <= self.monotonic()):
            raise ApplicationBuildAdmissionDenied("application build selection is foreign, stale or expired")
        facts = self._current_facts(selection.runtime_preparation_selection_handle, create_output=False, retained_selection=selection)
        try:
            if not self._matches(selection, facts):
                raise ApplicationBuildAdmissionDenied("application build inputs changed after selection")
            resolved = self._resolved_inputs(selection, facts)
            self._close_fact_fds(facts)
            return resolved
        except Exception:
            self._close_fact_fds(facts)
            raise

    def _current_facts(self, prep_handle: str, *, create_output: bool,
                       retained_selection: RootSelectedApplicationBuildSelection | None = None) -> dict[str, Any]:
        from .application_runtime_selection import (
            RootApplicationRuntimePreparationInputSelection,
            RootApplicationRuntimePreparationSelection,
        )
        from .application_source_preparation import (
            RootApplicationLockReceipt, RootPreparedApplicationSourceReceipt,
        )
        from .application_runtime_preparation import (
            RootApplicationOfflinePackageClosureReceipt,
            RootApplicationBuildBackendClosureReceipt,
            RootApplicationLockedPackageArtifactReceipt,
            RootApplicationBuildBackendArtifactReceipt,
        )
        from .application_toolchains import RootApplicationToolchainObservation
        from .bootstrap_runtime_factory import RootInstalledReleaseMemberReceipt
        try:
            if not isinstance(prep_handle, str):
                raise ValueError
            preparation = self.binding.resolve_application_runtime_preparation_selection(prep_handle)
            if (type(preparation) is not RootApplicationRuntimePreparationSelection
                    or preparation.selection_handle != prep_handle
                    or preparation.expires_monotonic <= self.monotonic()):
                raise ValueError
            finite = _APP_BUILD_PROFILES.get(preparation.application_id)
            if (finite is None or preparation.workflow_id != finite[0]
                    or preparation.runtime_kind != finite[1]
                    or preparation.build_profile_id != finite[2]
                    or preparation.operation_id != finite[2]
                    or preparation.target_id != finite[3]):
                raise ApplicationBuildAdmissionDenied("application build selection is outside the exact v132 finite profile")
            input_resolver = getattr(self.runtime_registry, "resolve_application_runtime_preparation_input", None)
            if not callable(input_resolver):
                raise ApplicationBuildAdmissionDenied("current early source/lock input selector is unavailable")
            early = input_resolver(preparation.qualification_choice_handle, preparation.application_id)
            if (type(early) is not RootApplicationRuntimePreparationInputSelection
                    or early.expires_monotonic <= self.monotonic()
                    or early.selection_handle == ""
                    or early.qualification_choice_handle != preparation.qualification_choice_handle
                    or early.application_id != preparation.application_id
                    or early.workflow_id != preparation.workflow_id
                    or early.plan_sha256 != preparation.plan_sha256
                    or early.prepared_generation_id != preparation.prepared_generation_id
                    or early.prepared_generation_digest != preparation.prepared_generation_digest
                    or early.controller_binding_handle != preparation.controller_binding_handle
                    or early.source_preparation_selection_handle != preparation.source_preparation_selection_handle
                    or early.prepared_source_receipt_handle != preparation.prepared_source_receipt_handle
                    or early.selected_lock_receipt_handle != preparation.selected_lock_receipt_handle
                    or early.lock_sha256 != preparation.lock_sha256
                    or early.setup_session_id != preparation.setup_session_id
                    or early.transaction_handle != preparation.transaction_handle
                    or early.prepared_generation_digest != preparation.prepared_generation_digest):
                raise ApplicationBuildAdmissionDenied("early input selection differs from final v132 preparation selection")
            source_selection = self.source_registry.resolve_selection(
                preparation.source_preparation_selection_handle)
            source = self.source_registry.resolve_current_prepared_source_for_selection(
                preparation.source_preparation_selection_handle)
            lock = self.source_registry.resolve_current_lock_for_selection(
                preparation.source_preparation_selection_handle, source.receipt_handle)
            lock_bytes = self.source_registry.read_current_lock_bytes(
                lock.receipt_handle, preparation.source_preparation_selection_handle,
                source.receipt_handle)
            if (type(source) is not RootPreparedApplicationSourceReceipt
                    or type(lock) is not RootApplicationLockReceipt
                    or source.receipt_handle != preparation.prepared_source_receipt_handle
                    or source.source_generation_manifest_sha256 != preparation.source_generation_manifest_sha256
                    or lock.receipt_handle != preparation.selected_lock_receipt_handle
                    or lock.lock_sha256 != preparation.lock_sha256
                    or hashlib.sha256(lock_bytes).hexdigest() != lock.lock_sha256):
                raise ApplicationBuildAdmissionDenied("current application source or selected lock no longer matches preparation")
            package = self.package_registry.resolve_current_package_closure_for_selection(
                preparation.source_preparation_selection_handle)
            if (type(package) is not RootApplicationOfflinePackageClosureReceipt
                    or package.receipt_handle != preparation.package_closure_receipt_handle
                    or package.source_receipt_handle != source.receipt_handle
                    or package.lock_receipt_handle != lock.receipt_handle
                    or package.lock_sha256 != lock.lock_sha256
                    or package.setup_session_id != preparation.setup_session_id
                    or package.transaction_handle != preparation.transaction_handle
                    or package.prepared_generation_digest != preparation.prepared_generation_digest
                    or package.application_id != preparation.application_id
                    or package.expires_monotonic <= self.monotonic()):
                raise ApplicationBuildAdmissionDenied("current runtime package closure is absent or detached")
            backend = None
            backend_handle = None
            if preparation.runtime_kind == "python":
                backend = self.backend_registry.resolve_current_backend_closure_for_selection(early.selection_handle)
                if (type(backend) is not RootApplicationBuildBackendClosureReceipt
                        or backend.application_id != preparation.application_id
                        or backend.source_preparation_selection_handle
                           != preparation.source_preparation_selection_handle
                        or backend.pyproject_receipt_handle != source.receipt_handle
                        or backend.qualification_choice_handle != preparation.qualification_choice_handle
                        or backend.expires_monotonic <= self.monotonic()):
                    raise ApplicationBuildAdmissionDenied("current separate PEP 517 backend closure is absent or detached")
                backend_handle = backend.receipt_handle
            elif preparation.runtime_kind == "node":
                raise ApplicationBuildAdmissionDenied(
                    "Hyperframes Node/Bun package closure and finite build driver are unavailable; Python backend path is not applicable")
            runtime = self.binding.resolve_current_pm_runtime()
            projection_resolver = getattr(self.binding, "resolve_current_pm_runtime_projection", None)
            if not callable(projection_resolver):
                raise ApplicationBuildAdmissionDenied("current held PM Python runtime closure projection is unavailable")
            projection = projection_resolver()
            from .pm_runtime import VerifiedPMRuntimeProjection
            if (type(projection) is not VerifiedPMRuntimeProjection
                    or getattr(projection, "selection", None) != runtime
                    or getattr(projection, "executable_relative_path", None) != "bin/python3.14"
                    or _digest(getattr(projection, "base_closure_sha256", None), "PM base runtime closure") == ""):
                raise ApplicationBuildAdmissionDenied("current held PM Python closure differs from its executable receipt")
            uv_resolver = getattr(self.binding, "resolve_current_pm_uv_tool_projection", None)
            if not callable(uv_resolver):
                raise ApplicationBuildAdmissionDenied("current held PM uv source projection is unavailable")
            uv = uv_resolver()
            from .pm_runtime import VerifiedPMUVToolProjection
            if (type(uv) is not VerifiedPMUVToolProjection
                    or uv.relative_path != "uv"
                    or uv.artifact_id != "hermes-pm-uv-linux-arm64"
                    or uv.sha256 != "20d0be6a6bd33f55e4ceb0e52ac2f733722b1a7959498e6401ecf84bc05e48a8"
                    or uv.transaction_handle != preparation.transaction_handle
                    or uv.prepared_generation_id != preparation.prepared_generation_id
                    or not isinstance(uv.source_receipt_handle, str)
                    or len(uv.source_receipt_handle) < 32
                    or not isinstance(uv.artifact_id, str) or not uv.artifact_id
                    or not isinstance(uv.fd, int)):
                raise ApplicationBuildAdmissionDenied("held PM uv projection is detached from current setup")
            uv_info = os.fstat(uv.fd)
            uv_hash = hashlib.sha256()
            uv_offset = 0
            while uv_offset < uv_info.st_size:
                block = os.pread(uv.fd, min(1024 * 1024, uv_info.st_size - uv_offset), uv_offset)
                if not block:
                    raise ApplicationBuildAdmissionDenied("held PM uv projection ended early")
                uv_hash.update(block)
                uv_offset += len(block)
            if (not stat.S_ISREG(uv_info.st_mode) or uv_info.st_uid != 0
                    or uv_info.st_dev != uv.device or uv_info.st_ino != uv.inode
                    or uv_info.st_size != uv.size_bytes or uv_info.st_gid != uv.gid
                    or stat.S_IMODE(uv_info.st_mode) != uv.mode
                    or uv_hash.hexdigest() != uv.sha256):
                uv.close()
                raise ApplicationBuildAdmissionDenied("held PM uv bytes differ from the exact current artifact receipt")
            runtime_handles = tuple(getattr(runtime, "receipt_handle", "") for _ in (0,)) + (
                getattr(uv, "receipt_handle", ""),)
            if (not all(isinstance(x, str) and len(x) >= 32 for x in runtime_handles)
                    or tuple(preparation.runtime_toolchain_receipt_handles) != runtime_handles
                    or getattr(runtime, "implementation", None) != "cpython"
                    or getattr(runtime, "version_info", ())[:2] != (3, 14)
                    or str(getattr(runtime, "machine", "")).lower() not in {"aarch64", "arm64"}
                    ):
                raise ApplicationBuildAdmissionDenied("current PM Python/uv selection differs from the retained preparation")
            toolchains: tuple[Any, ...] = ()
            if preparation.runtime_kind == "node":
                resolver = getattr(self.toolchain_registry, "resolve_current_toolchain_for_selection", None)
                if not callable(resolver):
                    raise ApplicationBuildAdmissionDenied("current selected Node/Bun toolchain resolver is unavailable")
                toolchains = resolver(early.selection_handle)
                if (not isinstance(toolchains, tuple)
                        or any(type(row) is not RootApplicationToolchainObservation for row in toolchains)):
                    raise ApplicationBuildAdmissionDenied("current Node/Bun toolchain receipts are not typed root observations")
            choice = self.binding.resolve_application_setup_choice(preparation.qualification_choice_handle)
            controller = self.binding.resolve_application_controller_binding(
                preparation.qualification_choice_handle)
            if (getattr(choice, "selection_handle", None) != preparation.qualification_choice_handle
                    or getattr(choice, "application_id", None) != preparation.application_id
                    or getattr(controller, "handle", None) != preparation.controller_binding_handle
                    or getattr(controller, "expires_monotonic", 0) <= self.monotonic()
                    or not self.binding.verify_application_controller_binding(controller)):
                raise ApplicationBuildAdmissionDenied("current signed app choice or controller binding changed")
            build = self.binding.resolve_prepared_application_build_service(preparation.build_profile_id)
            if (build.verify_current() is not build
                    or build.service_selection_handle != preparation.prepared_build_service_selection_handle
                    or build.setup_session_id != preparation.setup_session_id
                    or build.transaction_handle != preparation.transaction_handle
                    or build.prepared_generation_id != preparation.prepared_generation_id
                    or build.prepared_generation_digest != preparation.prepared_generation_digest
                    or build.id == "" or build.generation == ""):
                raise ApplicationBuildAdmissionDenied("current prepared application build subject changed")
            # Sol has not yet pinned the standalone source driver. Do not use a
            # worktree file, caller path, or qualification probe as its receipt.
            driver_resolver = getattr(self.binding, "resolve_installed_application_builder_module", None)
            if not callable(driver_resolver):
                raise ApplicationBuildAdmissionDenied(
                    "reviewed installed application environment builder source member is unavailable")
            driver = driver_resolver()
            if (type(driver) is not RootInstalledReleaseMemberReceipt
                    or driver.artifact_id != _DRIVER_ARTIFACT_ID
                    or driver.relative_path != _DRIVER_MEMBER_PATH
                    or driver.size_bytes <= 0):
                raise ApplicationBuildAdmissionDenied("installed application builder member is not the exact reviewed release pin")
            driver_bytes = driver.read_current()
            if (len(driver_bytes) != driver.size_bytes
                    or hashlib.sha256(driver_bytes).hexdigest() != driver.sha256):
                raise ApplicationBuildAdmissionDenied("installed app build driver bytes failed held receipt verification")
            source_members_meta = tuple(source.manifest_member_records)
            paths = tuple(row.get("path") for row in source_members_meta)
            source_bytes = self.source_registry.read_current_source_members(
                preparation.source_preparation_selection_handle, source.receipt_handle, paths)
            if len(source_bytes) != len(paths) or any(not isinstance(body, bytes) for body in source_bytes.values()):
                raise ApplicationBuildAdmissionDenied("current selected application source member bytes are incomplete")
            package_fds: list[tuple[Any, int]] = []
            backend_fds: list[tuple[Any, int]] = []
            try:
                for record in package.package_records:
                    artifact, fd = self.package_registry.resolve_package_artifact(
                        record.artifact_receipt_handle,
                        preparation.source_preparation_selection_handle,
                        package.receipt_handle)
                    if type(artifact) is not RootApplicationLockedPackageArtifactReceipt:
                        os.close(fd)
                        raise ApplicationBuildAdmissionDenied("runtime wheel resolver returned an untyped artifact")
                    package_fds.append((artifact, fd))
                if backend is not None:
                    for artifact_handle in backend.package_artifact_receipt_handles:
                        artifact, fd = self.backend_registry.resolve_backend_artifact(
                            artifact_handle, early.selection_handle, backend.receipt_handle)
                        if type(artifact) is not RootApplicationBuildBackendArtifactReceipt:
                            os.close(fd)
                            raise ApplicationBuildAdmissionDenied("backend wheel resolver returned an untyped artifact")
                        backend_fds.append((artifact, fd))
                output = (build.create_output_root() if retained_selection is None
                          else retained_selection.output_root)
                if (output.output_root_id != (preparation.output_root_receipt_handle
                                               if retained_selection is None
                                               else retained_selection.output_root_receipt_handle)
                        or output.service_selection_handle != build.service_selection_handle):
                    raise ApplicationBuildAdmissionDenied("held output-root FD differs from current v132 selection")
                output_fd = output.open_current()
                output_info = os.fstat(output_fd)
                if (not stat.S_ISDIR(output_info.st_mode) or output_info.st_uid != build.service_uid
                        or output_info.st_gid != build.service_gid or stat.S_IMODE(output_info.st_mode) != 0o700):
                    os.close(output_fd)
                    raise ApplicationBuildAdmissionDenied("current app output directory descriptor failed identity checks")
                profile = self._fixed_profile(preparation, build, source, driver, output, runtime, projection)
                return {
                    "prep": preparation, "selection": preparation, "source_selection": source_selection,
                    "source": source, "lock": lock, "package": package, "backend": backend,
                    "backend_handle": backend_handle, "toolchains": toolchains,
                    "runtime": runtime, "pm_runtime": runtime, "pm_projection": projection,
                    "pm_uv": uv, "pm_uv_projection": uv,
                    "choice": choice, "controller": controller, "service": build,
                    "build": build, "output": output, "output_fd": output_fd,
                    "driver": driver, "driver_bytes": driver_bytes,
                    "source_bytes": source_bytes, "source_members_meta": source_members_meta,
                    "package_fds": package_fds, "backend_fds": backend_fds,
                    "package_filenames": {artifact.receipt_handle:
                        urllib.parse.urlsplit(artifact.source_url).path.rsplit("/", 1)[-1]
                        for artifact, _fd in package_fds},
                    "profile": profile, "early": early, "output_fd": output_fd,
                }
            except Exception:
                for _artifact, fd in package_fds + backend_fds:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                if "output_fd" in locals():
                    try:
                        os.close(output_fd)
                    except OSError:
                        pass
                raise
        except ApplicationBuildAdmissionDenied:
            projection = locals().get("projection")
            if projection is not None:
                try:
                    projection.close()
                except Exception:
                    pass
            uv_projection = locals().get("uv")
            if uv_projection is not None:
                try:
                    uv_projection.close()
                except Exception:
                    pass
            raise
        except Exception as exc:
            projection = locals().get("projection")
            if projection is not None:
                try:
                    projection.close()
                except Exception:
                    pass
            uv_projection = locals().get("uv")
            if uv_projection is not None:
                try:
                    uv_projection.close()
                except Exception:
                    pass
            reason = str(exc).strip()
            if reason and len(reason) <= 300:
                raise ApplicationBuildAdmissionDenied(reason) from None
            raise ApplicationBuildAdmissionDenied(
                "application source, closure, PM, service or setup selection is not current") from None

    @staticmethod
    def _fixed_profile(preparation: Any, service: Any, source: Any,
                       driver: Any, output: Any, runtime: Any, projection: Any) -> Any:
        from ..protected_enrollment import FixedBuildOutputSpec, FixedBuildProfile
        generation = hashlib.sha256(_canonical({
            "application_id": preparation.application_id,
            "prepared_generation_digest": preparation.prepared_generation_digest,
            "service_generation": service.generation,
            "driver_sha256": driver.sha256,
            "python_runtime_closure_sha256": projection.base_closure_sha256,
            "source_manifest_sha256": source.source_generation_manifest_sha256,
            "build_profile_id": preparation.build_profile_id,
        })).hexdigest()
        return FixedBuildProfile(
            target_id=preparation.target_id, generation="app-setup-" + generation,
            build_service_enrollment_id=service.id,
            build_service_generation=service.generation,
            source_artifact_id=source.source_archive_artifact_id,
            source_sha256=source.source_archive_sha256,
            toolchain_artifact_id=_DRIVER_ARTIFACT_ID,
            toolchain_sha256=driver.sha256,
            builder_artifact_id="pm-runtime-" + runtime.receipt_handle,
            builder_sha256=runtime.runtime_sha256,
            argv_recipe=(
                {"build_path": {"mount_id": "builder", "relative_path": ""}},
                {"literal": "-I"},
                {"build_path": {"mount_id": "toolchain", "relative_path":
                                 "hermes_installer/authority/application_environment_builder.py"}},
            ),
            environment={}, max_lifetime_seconds=_MAX_LIFETIME_SECONDS,
            output_root_id=output.output_root_id, output_root=None,
            output_owner_uid=service.service_uid,
            output_specs={"runtime-environment.tar": FixedBuildOutputSpec(
                "runtime-environment.tar", "file", _MAX_RUNTIME_ARCHIVE_BYTES,
                None, {"application_id": preparation.application_id,
                       "source_manifest_sha256": source.source_generation_manifest_sha256,
                       "archive_bytes_max": _MAX_RUNTIME_ARCHIVE_BYTES})},
            service_generation_digest=preparation.prepared_generation_digest)

    @staticmethod
    def _recipe_digest(facts: Mapping[str, Any]) -> str:
        prep, source, lock, package = facts["prep"], facts["source"], facts["lock"], facts["package"]
        backend = facts["backend"]
        driver = facts["driver"]
        return hashlib.sha256(_canonical({
            "schema": 1,
            "application_id": prep.application_id,
            "build_profile_id": prep.build_profile_id,
            "operation_id": prep.operation_id,
            "target_id": prep.target_id,
            "source_receipt_handle": source.receipt_handle,
            "source_manifest_sha256": source.source_generation_manifest_sha256,
            "pm_runtime_closure_sha256": facts["pm_projection"].base_closure_sha256,
            "pm_runtime_executable_sha256": facts["pm_runtime"].runtime_sha256,
            "pm_uv_receipt_handle": getattr(facts["pm_uv"], "receipt_handle", None),
            "pm_uv_executable_sha256": getattr(facts["pm_uv"], "sha256", None),
            "lock_receipt_handle": lock.receipt_handle,
            "lock_sha256": lock.lock_sha256,
            "package_closure_receipt_handle": package.receipt_handle,
            "package_closure_sha256": package.package_closure_sha256,
            "build_backend_closure_receipt_handle": getattr(backend, "receipt_handle", None),
            "build_backend_closure_sha256": getattr(backend, "backend_closure_sha256", None),
            "runtime_toolchain_receipt_handles": list(prep.runtime_toolchain_receipt_handles),
            "python_runtime_executable_relative_path": "bin/python3.14",
            "builder_module_receipt_handle": driver.receipt_handle,
            "builder_module_sha256": driver.sha256,
            "output_root_receipt_handle": facts["output"].output_root_id,
            "fixed_recipe": "hermes-application-environment-builder-v1",
        })).hexdigest()

    @staticmethod
    def _matches(selection: RootSelectedApplicationBuildSelection,
                 facts: Mapping[str, Any]) -> bool:
        prep = facts["prep"]
        return (
            selection.runtime_preparation_selection_handle == prep.selection_handle
            and selection.setup_session_id == prep.setup_session_id
            and selection.transaction_handle == prep.transaction_handle
            and selection.plan_sha256 == prep.plan_sha256
            and selection.prepared_generation_id == prep.prepared_generation_id
            and selection.prepared_generation_digest == prep.prepared_generation_digest
            and selection.application_id == prep.application_id
            and selection.workflow_id == prep.workflow_id
            and selection.build_profile_id == prep.build_profile_id
            and selection.operation_id == prep.operation_id
            and selection.target_id == prep.target_id
            and selection.build_service_selection_handle == facts["service"].service_selection_handle
            and selection.build_service_enrollment_id == facts["service"].id
            and selection.build_service_generation == facts["service"].generation
            and selection.source_receipt_handle == facts["source"].receipt_handle
            and selection.source_manifest_sha256 == facts["source"].source_generation_manifest_sha256
            and selection.pm_runtime.receipt_handle == facts["pm_runtime"].receipt_handle
            and selection.pm_uv.receipt_handle == facts["pm_uv"].receipt_handle
            and selection.pm_runtime_closure_sha256 == facts["pm_projection"].base_closure_sha256
            and selection.lock_receipt_handle == facts["lock"].receipt_handle
            and selection.lock_sha256 == facts["lock"].lock_sha256
            and selection.package_closure_receipt_handle == facts["package"].receipt_handle
            and selection.build_backend_closure_receipt_handle == facts["backend_handle"]
            and selection.runtime_toolchain_receipt_handles == tuple(prep.runtime_toolchain_receipt_handles)
            and selection.builder_module_receipt_handle == facts["driver"].receipt_handle
            and selection.builder_module_sha256 == facts["driver"].sha256
            and selection.recipe_sha256 == RootApplicationBuildAdmissionRegistry._recipe_digest(facts)
            and selection.output_root_receipt_handle == facts["output"].output_root_id
            and selection.controller_binding_handle == prep.controller_binding_handle
        )

    def _resolved_inputs(self, selection: RootSelectedApplicationBuildSelection,
                         facts: Mapping[str, Any]) -> RootResolvedApplicationBuildInputs:
        owned: list[int] = []
        try:
            source_members = tuple(self._memfd_member(path, body,
                next((row for row in facts["source_members_meta"] if row.get("path") == path), {}))
                for path, body in sorted(facts["source_bytes"].items()))
            for row in source_members:
                owned.append(row.fd)
            package_members_list = []
            for artifact, fd in facts["package_fds"]:
                member = self._artifact_member(artifact, fd, "package")
                package_members_list.append(member)
                owned.append(member.fd)
            facts["package_fds"] = []
            backend_members_list = []
            for artifact, fd in facts["backend_fds"]:
                member = self._artifact_member(artifact, fd, "backend")
                backend_members_list.append(member)
                owned.append(member.fd)
            facts["backend_fds"] = []
            package_members = tuple(package_members_list)
            backend_members = tuple(backend_members_list)
            driver_fd = self._sealed_memfd("app-builder", facts["driver_bytes"])
            owned.append(driver_fd)
            output_fd = facts["output"].open_current()
            owned.append(output_fd)
            python_fd, python_sha = self._duplicate_verified_pm_python(
                facts["pm_projection"], facts["pm_runtime"])
            owned.append(python_fd)
            python_executable_member = RootApplicationBuildInputMember._mint(
                relative_path="bin/python3.14", fd=python_fd, sha256=python_sha,
                size_bytes=os.fstat(python_fd).st_size, executable=True,
                receipt_handle=facts["pm_runtime"].receipt_handle, kind="file")
            runtime_members = self._duplicate_verified_pm_runtime_members(facts["pm_projection"])
            owned.extend(row.fd for row in runtime_members)
            controller_pidfd, controller_claims = self._duplicate_controller_pidfd(
                facts["controller"], selection.controller_binding_handle)
            owned.append(controller_pidfd)
            uv_projection = facts["pm_uv_projection"]
            uv_fd = os.dup(uv_projection.fd)
            uv_info = os.fstat(uv_fd)
            if (not stat.S_ISREG(uv_info.st_mode) or uv_info.st_uid != 0
                    or uv_info.st_dev != uv_projection.device
                    or uv_info.st_ino != uv_projection.inode
                    or uv_info.st_size != uv_projection.size_bytes):
                os.close(uv_fd)
                raise ApplicationBuildAdmissionDenied("duplicated PM uv descriptor identity changed")
            uv_sha, uv_size = uv_projection.sha256, uv_projection.size_bytes
            owned.append(uv_fd)
            config = self._driver_config(selection, facts, python_sha, uv_sha)
            config_sha = hashlib.sha256(config).hexdigest()
            config_fd = self._sealed_memfd("app-build-recipe", config)
            owned.append(config_fd)
            recipe_member_fd = os.dup(config_fd)
            owned.append(recipe_member_fd)
            # Config is exposed as bytes and as an independently owned sealed member FD.
            recipe_member = RootApplicationBuildInputMember._mint(
                relative_path="application-build-input.json", fd=recipe_member_fd,
                sha256=config_sha, size_bytes=len(config), executable=False,
                receipt_handle=selection.selection_handle)
            return RootResolvedApplicationBuildInputs(
                selection_handle=selection.selection_handle,
                application_id=selection.application_id,
                build_profile_id=selection.build_profile_id,
                target_id=selection.target_id, operation_id=selection.operation_id,
                runtime_preparation_selection_handle=selection.runtime_preparation_selection_handle,
                plan_sha256=selection.plan_sha256,
                setup_session_id=selection.setup_session_id,
                transaction_handle=selection.transaction_handle,
                prepared_generation_id=selection.prepared_generation_id,
                prepared_generation_digest=selection.prepared_generation_digest,
                source_receipt_handle=selection.source_receipt_handle,
                source_manifest_sha256=selection.source_manifest_sha256,
                pm_runtime_closure_sha256=selection.pm_runtime_closure_sha256,
                lock_receipt_handle=selection.lock_receipt_handle,
                lock_sha256=selection.lock_sha256,
                package_closure_receipt_handle=selection.package_closure_receipt_handle,
                build_backend_closure_receipt_handle=selection.build_backend_closure_receipt_handle,
                recipe_sha256=selection.recipe_sha256,
                builder_fd=python_fd, builder_receipt_handle=facts["pm_runtime"].receipt_handle,
                builder_sha256=python_sha,
                builder_size_bytes=os.fstat(python_fd).st_size,
                python_executable_member=python_executable_member,
                source_members=source_members, package_members=package_members,
                backend_members=backend_members, python_runtime_members=runtime_members,
                uv_fd=uv_fd, uv_sha256=uv_sha, uv_size_bytes=uv_size,
                uv_source_receipt_handle=uv_projection.source_receipt_handle,
                uv_artifact_id=uv_projection.artifact_id,
                driver_fd=driver_fd, driver_receipt_handle=selection.builder_module_receipt_handle,
                driver_sha256=selection.builder_module_sha256,
                driver_size_bytes=len(facts["driver_bytes"]),
                recipe_config_bytes=config, recipe_config_sha256=config_sha,
                recipe_member=recipe_member, output_root_fd=output_fd, output_root_id=selection.output_root_receipt_handle,
                output_owner_uid=facts["service"].service_uid,
                output_owner_gid=facts["service"].service_gid,
                build_service_id=selection.build_service_enrollment_id,
                build_service_selection_handle=selection.build_service_selection_handle,
                build_service_generation=selection.build_service_generation,
                runtime_toolchain_receipt_handles=selection.runtime_toolchain_receipt_handles,
                controller_binding_handle=selection.controller_binding_handle,
                controller_pidfd=controller_pidfd, **controller_claims,
                _registry=self, _selection=selection,
                _owned_fds=tuple(owned), _seal=_INPUTS_SEAL)
        except Exception:
            for fd in owned:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise

    def _duplicate_controller_pidfd(self, controller: Any, expected_handle: str) -> tuple[int, dict[str, int]]:
        from .bootstrap_runtime_factory import RootApplicationSetupControllerBinding
        if (type(controller) is not RootApplicationSetupControllerBinding
                or controller.handle != expected_handle
                or controller.setup_session_id != self.binding.resolve_current_setup_session_handle().session_id
                or not self.binding.verify_application_controller_binding(controller)):
            raise ApplicationBuildAdmissionDenied("current root TTY controller proof is unavailable")
        proof = controller._proof
        if (getattr(proof, "controller_pid", None) != os.getpid()
                or getattr(proof, "controller_uid", None) != 0
                or not isinstance(getattr(proof, "controller_start_ticks", None), int)
                or not isinstance(getattr(proof, "controller_gid", None), int)):
            raise ApplicationBuildAdmissionDenied("root TTY controller identity is not the active root process")
        try:
            fd = os.dup(proof.pidfd)
            os.fstat(fd)
        except OSError:
            raise ApplicationBuildAdmissionDenied("root TTY controller pidfd is no longer held") from None
        return fd, {"controller_pid": proof.controller_pid,
                    "controller_start_ticks": proof.controller_start_ticks,
                    "controller_uid": proof.controller_uid,
                    "controller_gid": proof.controller_gid}

    @staticmethod
    def _artifact_member(artifact: Any, fd: int, kind: str) -> RootApplicationBuildInputMember:
        info = os.fstat(fd)
        digest = getattr(artifact, "artifact_sha256", getattr(artifact, "sha256", None))
        size = getattr(artifact, "size_bytes", None)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size != size
                or _digest(digest, f"{kind} artifact") == "" or not isinstance(size, int)):
            os.close(fd)
            raise ApplicationBuildAdmissionDenied(f"{kind} artifact descriptor failed root identity checks")
        filename = (getattr(artifact, "filename", None)
                    or urllib.parse.urlsplit(getattr(artifact, "source_url", "")).path.rsplit("/", 1)[-1])
        if (not isinstance(filename, str) or not filename.endswith(".whl")
                or filename in {"", ".", ".."} or "/" in filename or "\\" in filename):
            os.close(fd)
            raise ApplicationBuildAdmissionDenied(f"{kind} artifact has no finite wheel filename")
        return RootApplicationBuildInputMember._mint(
            relative_path=filename,
            fd=fd, sha256=digest, size_bytes=size, executable=False,
            receipt_handle=artifact.receipt_handle, kind="file", _seal=_INPUTS_SEAL)

    @staticmethod
    def _memfd_member(path: str, body: bytes, record: Mapping[str, Any]) -> RootApplicationBuildInputMember:
        fd = RootApplicationBuildAdmissionRegistry._sealed_memfd("app-source", body)
        digest = hashlib.sha256(body).hexdigest()
        expected = record.get("sha256")
        if expected != digest or record.get("size_bytes") != len(body):
            os.close(fd)
            raise ApplicationBuildAdmissionDenied("verified source member bytes differ from its manifest")
        return RootApplicationBuildInputMember._mint(
            relative_path=path, fd=fd, sha256=digest, size_bytes=len(body),
            executable=bool(record.get("executable", False)),
            receipt_handle=str(record.get("receipt_handle", "source-manifest")),
            kind="file", _seal=_INPUTS_SEAL)

    @staticmethod
    def _sealed_memfd(name: str, body: bytes) -> int:
        if not hasattr(os, "memfd_create") or not hasattr(fcntl, "F_ADD_SEALS"):
            raise ApplicationBuildAdmissionDenied("sealed anonymous input descriptors are unavailable on this host")
        fd = os.memfd_create(name, getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0))
        try:
            view = memoryview(body)
            offset = 0
            while offset < len(view):
                offset += os.write(fd, view[offset:])
            os.fsync(fd)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                         fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
                         fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
            info = os.fstat(fd)
            if (info.st_uid != 0 or not stat.S_ISREG(info.st_mode)
                    or info.st_size != len(body)
                    or hashlib.sha256(os.pread(fd, len(body), 0)).digest()
                       != hashlib.sha256(body).digest()):
                raise ApplicationBuildAdmissionDenied("sealed root input descriptor failed byte verification")
            return fd
        except Exception:
            os.close(fd)
            raise

    @staticmethod
    def _safe_projection_path(value: Any, label: str) -> str:
        if (not isinstance(value, str) or not value or value.startswith("/")
                or "\\" in value or "\x00" in value):
            raise ApplicationBuildAdmissionDenied(f"PM runtime {label} path is malformed")
        parts = value.split("/")
        if any(part in {"", ".", ".."} for part in parts) or posixpath.normpath(value) != value:
            raise ApplicationBuildAdmissionDenied(f"PM runtime {label} path is not normalized")
        return value

    def _duplicate_verified_pm_python(self, projection: Any, runtime: Any) -> tuple[int, str]:
        from .pm_runtime import VerifiedPMRuntimeProjectionMember
        member = getattr(projection, "executable_member", None)
        if (type(member) is not VerifiedPMRuntimeProjectionMember
                or member.relative_path != "bin/python3.14" or member.kind != "file"
                or not member.executable or not isinstance(member.fd, int)
                or member.sha256 != runtime.runtime_sha256):
            raise ApplicationBuildAdmissionDenied("selected PM projection lacks its exact executable member")
        fd = os.dup(member.fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_size != member.size_bytes
                    or info.st_uid != 0 or info.st_dev != member.device
                    or info.st_ino != member.inode or stat.S_IMODE(info.st_mode) != member.mode):
                raise ApplicationBuildAdmissionDenied("held PM interpreter descriptor identity changed")
            digest = hashlib.sha256()
            offset = 0
            while offset < info.st_size:
                block = os.pread(fd, min(1024 * 1024, info.st_size - offset), offset)
                if not block:
                    raise ApplicationBuildAdmissionDenied("held PM interpreter bytes ended early")
                digest.update(block)
                offset += len(block)
            actual = digest.hexdigest()
            if actual != member.sha256:
                raise ApplicationBuildAdmissionDenied("held PM interpreter bytes differ from the base closure receipt")
            return fd, actual
        except Exception:
            os.close(fd)
            raise

    def _duplicate_verified_pm_runtime_members(
            self, projection: Any) -> tuple[RootApplicationBuildInputMember, ...]:
        from .pm_runtime import VerifiedPMRuntimeProjectionMember
        rows = tuple(getattr(projection, "members", ()))
        if (not rows or any(type(row) is not VerifiedPMRuntimeProjectionMember for row in rows)
                or tuple(row.relative_path for row in rows)
                   != tuple(sorted(row.relative_path for row in rows))):
            raise ApplicationBuildAdmissionDenied("PM base runtime projection is incomplete or not canonically ordered")
        by_path = {self._safe_projection_path(row.relative_path, "member") : row for row in rows}
        executable = by_path.get("bin/python3.14")
        if executable is not getattr(projection, "executable_member", None):
            raise ApplicationBuildAdmissionDenied("PM executable is detached from the projected runtime tree")
        def held_regular_target(path: str, seen: frozenset[str] = frozenset()) -> bool:
            if path in seen:
                return False
            target_row = by_path.get(path)
            if target_row is None:
                # Directory rows are implicit in the pinned file tree. Accept
                # them only when the closure contains a receipt-backed child.
                return any(candidate.startswith(path.rstrip("/") + "/")
                           for candidate in by_path)
            if target_row.kind == "file":
                return True
            if target_row.kind != "symlink" or not isinstance(target_row.link_target, str):
                return False
            target_path = posixpath.normpath(
                posixpath.join(posixpath.dirname(path), target_row.link_target))
            if target_path in {".", ".."} or target_path.startswith("../"):
                return False
            return held_regular_target(target_path, seen | {path})

        result: list[RootApplicationBuildInputMember] = []
        try:
            for path, row in by_path.items():
                if path == "bin/python3.14":
                    continue
                if row.kind not in {"file", "symlink"} or not isinstance(row.sha256, str):
                    raise ApplicationBuildAdmissionDenied("PM runtime member has an unsupported file kind")
                target = row.link_target
                if row.kind == "file":
                    if (not isinstance(row.fd, int) or target is not None):
                        raise ApplicationBuildAdmissionDenied("PM regular runtime member lacks its held file descriptor")
                    fd = os.dup(row.fd)
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                            or info.st_dev != row.device or info.st_ino != row.inode
                            or info.st_size != row.size_bytes or stat.S_IMODE(info.st_mode) != row.mode):
                        os.close(fd)
                        raise ApplicationBuildAdmissionDenied("held PM runtime file identity changed")
                    digest = hashlib.sha256()
                    offset = 0
                    while offset < info.st_size:
                        block = os.pread(fd, min(1024 * 1024, info.st_size - offset), offset)
                        if not block:
                            os.close(fd)
                            raise ApplicationBuildAdmissionDenied("held PM runtime file ended early")
                        digest.update(block)
                        offset += len(block)
                    if digest.hexdigest() != row.sha256:
                        os.close(fd)
                        raise ApplicationBuildAdmissionDenied("held PM runtime file digest changed")
                else:
                    if not isinstance(row.fd, int) or not isinstance(target, str):
                        raise ApplicationBuildAdmissionDenied("PM runtime symlink lacks its no-follow descriptor")
                    fd = os.dup(row.fd)
                    info = os.fstat(fd)
                    target_bytes = target.encode("utf-8", "strict")
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
                    if (not stat.S_ISLNK(info.st_mode) or info.st_uid != 0
                            or info.st_dev != row.device or info.st_ino != row.inode
                            or row.size_bytes != len(target_bytes)
                            or hashlib.sha256(target_bytes).hexdigest() != row.sha256
                            or target.startswith("/") or "\\" in target
                            or posixpath.normpath(target) != target
                            or resolved in {".", ".."} or resolved.startswith("../")
                            or not held_regular_target(resolved)):
                        os.close(fd)
                        raise ApplicationBuildAdmissionDenied("PM runtime symlink escapes or lacks a held in-root target")
                result.append(RootApplicationBuildInputMember._mint(
                    relative_path=path, fd=fd, sha256=row.sha256, size_bytes=row.size_bytes,
                    executable=bool(row.executable), receipt_handle=projection.selection.receipt_handle,
                    kind=row.kind, link_target=target))
            return tuple(result)
        except Exception:
            for member in result:
                try:
                    os.close(member.fd)
                except OSError:
                    pass
            raise

    @staticmethod
    def _driver_config(selection: RootSelectedApplicationBuildSelection,
                       facts: Mapping[str, Any], python_sha: str, uv_sha: str) -> bytes:
        package_rows = [{"name": row.package_name, "version": row.package_version,
                         "filename": facts["package_filenames"][row.artifact_receipt_handle],
                         "sha256": row.artifact_sha256, "size_bytes": row.size_bytes}
                        for row in facts["package"].package_records]
        backend_rows = []
        if facts["backend"] is not None:
            for handle in facts["backend"].package_artifact_receipt_handles:
                entry = next(row for row, _fd in facts["backend_fds"]
                             if row.receipt_handle == handle)
                backend_rows.append({"name": entry.package_name, "version": entry.package_version,
                                     "filename": entry.filename, "sha256": entry.sha256,
                                     "size_bytes": entry.size_bytes})
        return _canonical({
            "schema": 1, "application_id": selection.application_id,
            "source_manifest_sha256": selection.source_manifest_sha256,
            "lock_sha256": selection.lock_sha256,
            "package_closure_sha256": facts["package"].package_closure_sha256,
            "backend_closure_sha256": getattr(facts["backend"], "backend_closure_sha256", None),
            "packages": package_rows, "backend_packages": backend_rows,
            "recipe_sha256": selection.recipe_sha256,
            "uv_executable_sha256": uv_sha,
            "python_executable_sha256": python_sha,
            "python_runtime_closure_sha256": facts["pm_projection"].base_closure_sha256,
            "python_runtime_executable_relative_path": "bin/python3.14",
        })

    @staticmethod
    def _close_fact_fds(facts: Mapping[str, Any]) -> None:
        projection = facts.get("pm_projection")
        if projection is not None:
            try:
                projection.close()
            except Exception:
                pass
        uv_projection = facts.get("pm_uv_projection")
        if uv_projection is not None:
            try:
                uv_projection.close()
            except Exception:
                pass
        for key in ("output_fd",):
            fd = facts.get(key)
            if isinstance(fd, int):
                try:
                    os.close(fd)
                except OSError:
                    pass
        for key in ("package_fds", "backend_fds"):
            for _artifact, fd in facts.get(key, ()):
                try:
                    os.close(fd)
                except OSError:
                    pass


class RootApplicationSetupBuildGrantIssuer:
    """Issue one short-lived HMAC-bound setup grant for a held app selection."""

    def __init__(self, admission: RootApplicationBuildAdmissionRegistry, *,
                 signing_key: bytes | None = None, monotonic=time.monotonic):
        if type(admission) is not RootApplicationBuildAdmissionRegistry or os.geteuid() != 0:
            raise ApplicationBuildAdmissionDenied("root application setup grant issuer is unavailable")
        key = secrets.token_bytes(32) if signing_key is None else signing_key
        if not isinstance(key, bytes) or len(key) != 32:
            raise ApplicationBuildAdmissionDenied("root application setup grant signing key is invalid")
        self.admission = admission
        self._key = bytes(key)
        self.monotonic = monotonic
        self.issuer_id = secrets.token_urlsafe(24)
        self._issued: dict[str, RootApplicationSetupBuildGrant] = {}
        self._issued_selections: set[str] = set()
        self._spent: set[str] = set()

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        application_build_admission_registry: RootApplicationBuildAdmissionRegistry,
                        **kwargs: Any) -> "RootApplicationSetupBuildGrantIssuer":
        if (type(application_build_admission_registry) is not RootApplicationBuildAdmissionRegistry
                or application_build_admission_registry.binding is not selected_installation_binding):
            raise ApplicationBuildAdmissionDenied("setup build grant issuer is not bound to the selected setup session")
        return cls(application_build_admission_registry, **kwargs)

    def issue(self, selection: RootSelectedApplicationBuildSelection) -> RootApplicationSetupBuildGrant:
        if selection.selection_handle in self._issued_selections:
            raise ApplicationBuildAdmissionDenied("a setup build grant was already issued for this selection")
        inputs = self.admission.verify_current(selection)
        inputs.close()
        now = self.monotonic()
        body = {
            "grant_id": secrets.token_urlsafe(32),
            "selection_handle": selection.selection_handle,
            "runtime_preparation_selection_handle": selection.runtime_preparation_selection_handle,
            "setup_session_id": selection.setup_session_id,
            "transaction_handle": selection.transaction_handle,
            "prepared_generation_id": selection.prepared_generation_id,
            "prepared_generation_digest": selection.prepared_generation_digest,
            "build_service_id": selection.build_service_enrollment_id,
            "build_service_generation": selection.build_service_generation,
            "target": selection.target_id,
            "operation_id": selection.operation_id,
            "parameters_digest": hashlib.sha256(_canonical({})).hexdigest(),
            "recipe_sha256": selection.recipe_sha256,
            "controller_binding_handle": selection.controller_binding_handle,
            "expires_monotonic": min(selection.expires_monotonic, now + 30.0),
        }
        signature = hmac.new(self._key, _canonical(body), hashlib.sha256).hexdigest()
        grant = RootApplicationSetupBuildGrant(
            **body, _issuer_id=self.issuer_id, _signature=signature, _seal=_GRANT_SEAL)
        self._issued[grant.grant_id] = grant
        self._issued_selections.add(selection.selection_handle)
        return grant

    def consume(self, grant: RootApplicationSetupBuildGrant,
                selection: RootSelectedApplicationBuildSelection) -> RootApplicationSetupBuildGrant:
        if (type(grant) is not RootApplicationSetupBuildGrant or grant._seal is not _GRANT_SEAL
                or grant._issuer_id != self.issuer_id
                or self._issued.get(grant.grant_id) is not grant
                or grant.grant_id in self._spent or self.monotonic() >= grant.expires_monotonic
                or type(selection) is not RootSelectedApplicationBuildSelection
                or grant.selection_handle != selection.selection_handle
                or grant.runtime_preparation_selection_handle != selection.runtime_preparation_selection_handle
                or grant.setup_session_id != selection.setup_session_id
                or grant.transaction_handle != selection.transaction_handle
                or grant.prepared_generation_id != selection.prepared_generation_id
                or grant.prepared_generation_digest != selection.prepared_generation_digest
                or grant.build_service_id != selection.build_service_enrollment_id
                or grant.build_service_generation != selection.build_service_generation
                or grant.target != selection.target_id or grant.operation_id != selection.operation_id
                or grant.parameters_digest != hashlib.sha256(_canonical({})).hexdigest()
                or grant.recipe_sha256 != selection.recipe_sha256
                or grant.controller_binding_handle != selection.controller_binding_handle):
            raise ApplicationBuildAdmissionDenied("application setup build grant is stale, forged, mismatched, or spent")
        body = {name: getattr(grant, name) for name in (
            "grant_id", "selection_handle", "runtime_preparation_selection_handle",
            "setup_session_id", "transaction_handle", "prepared_generation_id",
            "prepared_generation_digest", "build_service_id", "build_service_generation",
            "target", "operation_id", "parameters_digest", "recipe_sha256",
            "controller_binding_handle", "expires_monotonic")}
        if not hmac.compare_digest(grant._signature,
                                   hmac.new(self._key, _canonical(body), hashlib.sha256).hexdigest()):
            raise ApplicationBuildAdmissionDenied("application setup build grant signature is invalid")
        inputs = self.admission.verify_current(selection)
        inputs.close()
        self._spent.add(grant.grant_id)
        return grant
