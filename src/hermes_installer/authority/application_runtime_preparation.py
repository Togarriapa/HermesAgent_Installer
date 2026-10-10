"""Strict lock inventory helpers for pre-active application runtimes.

This module intentionally does not treat a lockfile as proof that packages
were acquired, licensed, or installed. It identifies the exact compatible
wheel bytes a later root-held package receipt must acquire and inspect.
"""
from __future__ import annotations

import ast
import base64
import binascii
import csv
import email
import email.policy
import hashlib
import io
import json
import os
import re
import secrets
import ssl
import stat
import tomllib
import time
import urllib.parse
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from hermes_installer.protected_enrollment import RootJournalSelection


_MAX_LOCK_BYTES = 16 * 1024 * 1024
_MAX_LOCK_PACKAGES = 8192
_MAX_MARKER_DEPTH = 32
_TARGET_GLIBC_MINOR = 36
_MAX_PACKAGE_ARCHIVE_BYTES = 2 * 1024**3
_MAX_ARCHIVE_MEMBERS = 131_072
_MAX_ARCHIVE_EXPANDED_BYTES = 2 * 1024**3
_MAX_LICENSE_MEMBER_BYTES = 16 * 1024**2
_MAX_LICENSE_EVIDENCE_BYTES = 64 * 1024**2
_PACKAGE_ORIGIN_POLICY_ID = "installer-locked-public-package-origin-v1"
_PACKAGE_PHASE_ID = "acquire-locked-runtime-packages"
_ROOT_PACKAGE_OWNER = 0
_PACKAGE_ARTIFACT_DOMAIN = "root-application-locked-package-artifact-v136"
_PACKAGE_LICENSE_DOMAIN = "root-application-package-license-observation-v136"


def _valid_opaque(value: Any) -> bool:
    return (isinstance(value, str) and 32 <= len(value) <= 128
            and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
_PYTHON_LOCK_APPS = frozenset({"graphify", "browser-use", "scrapegraph-ai"})
_MARKER_ENV = {
    "python_version": "3.14",
    "python_full_version": "3.14.0",
    "implementation_name": "cpython",
    "platform_python_implementation": "CPython",
    "sys_platform": "linux",
    "platform_system": "Linux",
    "platform_machine": "aarch64",
    "os_name": "posix",
    "extra": "",
}


class ApplicationRuntimePreparationDenied(PermissionError):
    """A selected lock cannot be mapped to a finite Linux ARM64 wheel closure."""


class _FrozenClaimMap(dict[str, Any]):
    """JSON-compatible immutable mapping used inside signed claim tuples."""

    def _deny(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("signed claim mappings are immutable")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = _deny


@dataclass(frozen=True, slots=True)
class LockedPythonWheel:
    package_name: str
    package_version: str
    url: str
    integrity_algorithm: str
    integrity_digest: str
    size_bytes: int
    wheel_filename: str
    selected_tag: str


@dataclass(frozen=True, slots=True)
class LockedPythonWheelSelection:
    application_id: str
    lock_sha256: str
    environment: tuple[tuple[str, str], ...]
    wheels: tuple[LockedPythonWheel, ...]
    blockers: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.blockers


@dataclass(frozen=True, slots=True)
class PythonPackageLicenseEvidence:
    """Observed wheel metadata and license-file facts, without an eligibility verdict."""

    artifact_sha256: str
    package_name: str
    package_version: str
    metadata_kind: str
    metadata_member_path: str
    metadata_member_sha256: str
    declared_license_expression: str | None
    license_member_records: tuple[tuple[str, str, int], ...]
    evidence_sha256: str
    eligibility: str


@dataclass(frozen=True, slots=True)
class ApplicationBuildBackendRequirements:
    """Source-observed PEP 517 requirements; not package or license receipts."""

    application_id: str
    backend: str
    requirements: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BackendWheelInspection:
    package_name: str
    package_version: str
    filename: str
    artifact_sha256: str
    size_bytes: int
    requires_python: str | None
    requires_dist: tuple[str, ...]
    metadata_member_path: str
    metadata_member_sha256: str
    declared_license_expression: str | None
    license_member_records: tuple[tuple[str, str, int], ...]


_PYTHON_BUILD_BACKENDS: Mapping[str, tuple[str, tuple[str, ...]]] = {
    "graphify": ("setuptools.build_meta", ("setuptools>=83.0.0",)),
    "browser-use": ("hatchling.build", ("hatchling==1.32.0",)),
    "scrapegraph-ai": ("hatchling.build", ("hatchling==1.26.3",)),
}


def inspect_application_build_backend(
    application_id: str, pyproject_bytes: bytes,
) -> ApplicationBuildBackendRequirements:
    """Match the pinned source manifest to its finite reviewed PEP 517 shape.

    This rejects source drift. The returned requirements are deliberately not
    treated as acquired wheels, a complete backend dependency closure, or a
    license approval; those need separate root-held package observations.
    """
    expected = _PYTHON_BUILD_BACKENDS.get(application_id)
    if (expected is None or not isinstance(pyproject_bytes, bytes)
            or not 1 <= len(pyproject_bytes) <= 1024 * 1024):
        raise ApplicationRuntimePreparationDenied(
            "application has no finite reviewed Python project build profile")
    try:
        project = tomllib.loads(pyproject_bytes.decode("utf-8"))
        build_system = project.get("build-system")
        if not isinstance(build_system, dict):
            raise ValueError
        backend = build_system.get("build-backend")
        requirements = build_system.get("requires")
        if (backend != expected[0] or not isinstance(requirements, list)
                or tuple(requirements) != expected[1]
                or any(not isinstance(item, str) for item in requirements)):
            raise ValueError
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError, TypeError):
        raise ApplicationRuntimePreparationDenied(
            "pinned source PEP 517 backend requirements changed or are unsupported") from None
    return ApplicationBuildBackendRequirements(application_id, backend, tuple(requirements))


def inspect_reviewed_backend_wheel(payload: bytes, package_source: Mapping[str, Any]) -> BackendWheelInspection:
    """Verify exact v152 source-table bytes, METADATA and license members.

    This yields byte-level source facts only. Registry acquisition, CAS custody,
    currentness and closure membership remain separate root receipts.
    """
    required = {
        "name", "version", "filename", "url", "sha256", "size_bytes",
        "requires_python", "requires_dist", "license_expression",
        "license_declaration", "license_members",
    }
    if (not isinstance(package_source, Mapping) or not required.issubset(package_source)
            or not isinstance(payload, bytes)
            or len(payload) != package_source["size_bytes"]
            or hashlib.sha256(payload).hexdigest() != package_source["sha256"]
            or not isinstance(package_source["filename"], str)
            or package_source["requires_dist"] is not None
               and not isinstance(package_source["requires_dist"], list)
            or not isinstance(package_source["license_members"], list)):
        raise ApplicationRuntimePreparationDenied("backend wheel bytes differ from the reviewed source table")
    try:
        # Enforce the v157 compressed-artifact expansion and member ceilings
        # before any metadata/license parser reads member bodies.
        with zipfile.ZipFile(io.BytesIO(payload), "r") as bounded_archive:
            bounded_entries = bounded_archive.infolist()
            if not 1 <= len(bounded_entries) <= 2048:
                raise ValueError
            bounded_names: set[str] = set()
            bounded_total = 0
            for item in bounded_entries:
                name = item.filename
                mode = (item.external_attr >> 16) & 0xFFFF
                kind = mode & 0o170000
                if (not name or name.startswith("/") or "\\" in name
                        or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
                        or name in bounded_names or item.flag_bits & 0x1
                        or item.file_size < 0 or item.compress_size < 0
                        or item.is_dir() and kind not in {0, 0o040000}
                        or not item.is_dir() and kind not in {0, 0o100000}):
                    raise ValueError
                bounded_names.add(name)
                bounded_total += item.file_size
                if bounded_total > 16 * 1024 * 1024:
                    raise ValueError
        evidence = observe_python_wheel_license(
            payload, expected_artifact_sha256=package_source["sha256"],
            expected_package_name=package_source["name"],
            expected_package_version=package_source["version"])
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            entries = archive.infolist()
            if not 1 <= len(entries) <= 2048:
                raise ValueError
            names: set[str] = set()
            expanded = 0
            for item in entries:
                name = item.filename
                mode = (item.external_attr >> 16) & 0xFFFF
                kind = mode & 0o170000
                if (not name or name.startswith("/") or "\\" in name
                        or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
                        or name in names or item.flag_bits & 0x1
                        or item.file_size < 0 or item.compress_size < 0
                        or item.is_dir() and kind not in {0, 0o040000}
                        or not item.is_dir() and kind not in {0, 0o100000}):
                    raise ValueError
                names.add(name)
                expanded += item.file_size
                if expanded > 16 * 1024 * 1024:
                    raise ValueError
            records = [item for item in entries if item.filename.endswith(".dist-info/RECORD")]
            if len(records) != 1 or records[0].file_size > 2 * 1024 * 1024:
                raise ValueError
            record_bytes = archive.read(records[0])
            record_rows = list(csv.reader(io.StringIO(record_bytes.decode("utf-8", "strict"))))
            record_by_path: dict[str, tuple[str, str]] = {}
            for row in record_rows:
                if len(row) != 3 or row[0] in record_by_path:
                    raise ValueError
                record_by_path[row[0]] = (row[1], row[2])
            regular_names = {item.filename for item in entries if not item.is_dir()}
            if regular_names != set(record_by_path):
                raise ValueError
            for item in entries:
                if item.is_dir():
                    continue
                record_hash, record_size = record_by_path[item.filename]
                body = archive.read(item)
                if len(body) != item.file_size:
                    raise ValueError
                if item.filename == records[0].filename:
                    if record_hash or record_size:
                        raise ValueError
                    continue
                if not record_hash.startswith("sha256=") or not record_size.isdecimal():
                    raise ValueError
                encoded = record_hash.removeprefix("sha256=")
                decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
                if (len(decoded) != 32 or decoded != hashlib.sha256(body).digest()
                        or int(record_size) != len(body)):
                    raise ValueError
            metadata_bytes = archive.read(evidence.metadata_member_path)
        metadata = email.message_from_bytes(metadata_bytes, policy=email.policy.default)
        requires_python = metadata.get("Requires-Python")
        requires_dist = tuple(value.strip() for value in metadata.get_all("Requires-Dist", []))
        expected_license = (package_source["license_expression"]
                            if package_source["license_expression"] is not None
                            else package_source["license_declaration"])
        observed_licenses = tuple(sorted(evidence.license_member_records))
        expected_licenses = tuple(sorted(
            (row["path"], row["sha256"], row["size_bytes"])
            for row in package_source["license_members"]
            if isinstance(row, dict) and set(row) == {"path", "sha256", "size_bytes"}))
        expected_requires_dist = tuple(package_source["requires_dist"] or ())
        if (requires_python != package_source["requires_python"]
                or requires_dist != expected_requires_dist
                or evidence.declared_license_expression != expected_license
                or len(expected_licenses) != len(package_source["license_members"])
                or observed_licenses != expected_licenses):
            raise ValueError
    except Exception:
        raise ApplicationRuntimePreparationDenied(
            "backend wheel metadata or license members differ from the reviewed source table") from None
    return BackendWheelInspection(
        package_source["name"], package_source["version"], package_source["filename"],
        package_source["sha256"], len(payload), requires_python, requires_dist,
        evidence.metadata_member_path, evidence.metadata_member_sha256,
        evidence.declared_license_expression, observed_licenses)


@dataclass(frozen=True, slots=True)
class RootApplicationLockedPackageArtifactReceipt:
    receipt_handle: str
    artifact_id: str
    application_id: str
    source_preparation_selection_handle: str
    qualification_choice_handle: str
    qualification_consent_receipt_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_digest: str
    lock_receipt_handle: str
    lock_sha256: str
    lock_member_id: str
    package_name: str
    package_version: str
    artifact_kind: str
    platform_tags: tuple[str, ...]
    origin_policy_id: str
    source_url: str
    lock_integrity_algorithm: str
    lock_integrity_digest: str
    artifact_sha256: str
    size_bytes: int
    cas_device: int
    cas_inode: int
    cas_mode: int
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str

    def claims(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__
                if name != "signature"}


@dataclass(frozen=True, slots=True)
class RootApplicationPackageLicenseObservation:
    receipt_handle: str
    artifact_receipt_handle: str
    artifact_sha256: str
    package_name: str
    package_version: str
    metadata_kind: str
    metadata_member_path: str
    metadata_member_sha256: str
    declared_license_expression: str | None
    license_member_records: tuple[Mapping[str, Any], ...]
    evidence_sha256: str
    eligibility: str
    review_policy_receipt_handle: str | None
    issued_monotonic: float
    expires_monotonic: float
    signature: str

    def claims(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__
                if name != "signature"}


@dataclass(frozen=True, slots=True)
class RootApplicationOfflinePackageRecord:
    package_name: str
    package_version: str
    lock_member_id: str
    lock_integrity_algorithm: str
    lock_integrity_digest: str
    artifact_receipt_handle: str
    artifact_sha256: str
    size_bytes: int
    artifact_kind: str
    platform_tags: tuple[str, ...]
    license_receipt_handle: str


@dataclass(frozen=True, slots=True)
class RootApplicationOfflinePackageClosureReceipt:
    receipt_handle: str
    source_preparation_selection_handle: str
    setup_session_id: str
    transaction_handle: str
    prepared_generation_digest: str
    application_id: str
    source_receipt_handle: str
    lock_receipt_handle: str
    lock_sha256: str
    platform: str
    runtime_toolchain_receipt_handles: tuple[str, ...]
    package_records: tuple[RootApplicationOfflinePackageRecord, ...]
    package_closure_sha256: str
    issued_monotonic: float
    expires_monotonic: float


@dataclass(slots=True)
class _PackageArtifactEntry:
    observation: RootApplicationLockedPackageArtifactReceipt
    receipt: RootApplicationLockedPackageArtifactReceipt | None
    fd: int
    phase_consent: Any


@dataclass(slots=True)
class _PackageLicenseEntry:
    observation: RootApplicationPackageLicenseObservation
    receipt: RootApplicationPackageLicenseObservation | None
    artifact_receipt_handle: str


@dataclass(slots=True)
class _PackageClosureEntry:
    selection: Any
    receipt: RootApplicationOfflinePackageClosureReceipt
    artifact_handles: tuple[str, ...]
    license_handles: tuple[str, ...]


class RootApplicationOfflinePackageClosureRegistry:
    """Acquire and retain only current lock-selected Python wheel bytes.

    This registry produces transport and license observations. It does not
    confer a reviewed license verdict, environment installation, or workload
    activation.
    """

    def __init__(self, *, selected_installation_binding: Any,
                 source_preparation_registry: Any, artifact_observer: Any,
                 root_journal: RootJournalSelection, authority_service: Any,
                 expected_uid: int = 0, monotonic=time.monotonic,
                 ttl_seconds: float = 900.0, download_timeout: float = 30.0) -> None:
        if (expected_uid != 0 or os.geteuid() != expected_uid
                or type(root_journal) is not RootJournalSelection
                or not isinstance(root_journal.path, Path) or not root_journal.path.is_absolute()
                or not callable(getattr(selected_installation_binding,
                                        "resolve_application_qualification_consent", None))
                or not callable(getattr(source_preparation_registry, "resolve_selection", None))
                or not callable(getattr(source_preparation_registry, "read_current_lock_bytes", None))
                or not callable(getattr(authority_service, "application_package_observation_signer", None))
                or not 0 < ttl_seconds <= 3600 or not 0 < download_timeout <= 120):
            raise ValueError("root locked-package closure bindings are unavailable")
        self.binding = selected_installation_binding
        self.source_registry = source_preparation_registry
        self.artifact_observer = artifact_observer
        self.root_journal = root_journal
        self.authority_service = authority_service
        self.expected_uid = expected_uid
        self.monotonic = monotonic
        self.ttl_seconds = float(ttl_seconds)
        self.download_timeout = float(download_timeout)
        self.signer = authority_service.application_package_observation_signer()
        self._artifact_entries: dict[str, _PackageArtifactEntry] = {}
        self._license_entries: dict[str, _PackageLicenseEntry] = {}
        self._closure_entries: dict[str, _PackageClosureEntry] = {}
        self._pending_artifacts: dict[str, RootApplicationLockedPackageArtifactReceipt] = {}
        self._pending_licenses: dict[str, RootApplicationPackageLicenseObservation] = {}
        self._cas_fd = -1

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        source_preparation_registry: Any, artifact_observer: Any,
                        root_journal: RootJournalSelection, authority_service: Any,
                        **kwargs: Any) -> "RootApplicationOfflinePackageClosureRegistry":
        registry = cls(selected_installation_binding=selected_installation_binding,
                       source_preparation_registry=source_preparation_registry,
                       artifact_observer=artifact_observer, root_journal=root_journal,
                       authority_service=authority_service, **kwargs)
        binding_attach = getattr(selected_installation_binding,
                                 "attach_application_package_closure_registry", None)
        if not callable(binding_attach):
            registry.close()
            raise ValueError("root setup binding has no typed application-package closure attachment")
        binding_attach(registry)
        attach = getattr(authority_service, "attach_application_package_closure_registry", None)
        if not callable(attach):
            registry.close()
            raise ValueError("authority service has no typed application-package receipt attachment")
        attach(registry)
        return registry

    def resolve_current_package_closure_for_selection(
        self, source_preparation_selection_handle: str,
    ) -> RootApplicationOfflinePackageClosureReceipt:
        """Return the sole retained, current package closure for an early app selector.

        This is the factory join point between package acquisition and the final
        v132 runtime selection. It never creates or refreshes a closure.
        """
        if not _valid_opaque(source_preparation_selection_handle):
            raise ApplicationRuntimePreparationDenied("source preparation handle is malformed")
        current_selection = self.source_registry.resolve_selection(
            source_preparation_selection_handle)
        candidates = [entry for entry in self._closure_entries.values()
                      if entry.selection == current_selection
                      and entry.receipt.source_preparation_selection_handle
                      == source_preparation_selection_handle]
        if len(candidates) != 1:
            raise ApplicationRuntimePreparationDenied(
                "current source selection has no unique retained package closure")
        return self.resolve_selected_packages(
            candidates[0].receipt.receipt_handle,
            source_preparation_selection_handle)

    def close(self) -> None:
        for entry in self._artifact_entries.values():
            if entry.fd >= 0:
                os.close(entry.fd)
                entry.fd = -1
        if self._cas_fd >= 0:
            os.close(self._cas_fd)
            self._cas_fd = -1

    def _open_cas_directory(self) -> int:
        path = self.root_journal.path
        try:
            info = path.stat(follow_symlinks=False)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o700
                    or (info.st_dev, info.st_ino) != (self.root_journal.device,
                                                       self.root_journal.inode)):
                raise OSError
            parent_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            current = os.fstat(parent_fd)
            if (current.st_uid != 0 or stat.S_IMODE(current.st_mode) != 0o700
                    or (current.st_dev, current.st_ino) != (self.root_journal.device,
                                                             self.root_journal.inode)):
                os.close(parent_fd)
                raise OSError
            for name in ("application-runtime-packages", "sha256"):
                try:
                    os.mkdir(name, 0o700, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   dir_fd=parent_fd)
                child = os.fstat(child_fd)
                if (child.st_uid != 0 or stat.S_IMODE(child.st_mode) != 0o700):
                    os.close(child_fd)
                    os.close(parent_fd)
                    raise OSError
                os.close(parent_fd)
                parent_fd = child_fd
            return parent_fd
        except OSError:
            raise ApplicationRuntimePreparationDenied("root package CAS directory is not private or current") from None

    def _require_cas_current(self) -> None:
        if self._cas_fd < 0:
            self._cas_fd = self._open_cas_directory()
        info = os.fstat(self._cas_fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ApplicationRuntimePreparationDenied("root package CAS directory identity changed")
        current = self.root_journal.path.stat(follow_symlinks=False)
        if ((current.st_dev, current.st_ino) != (self.root_journal.device, self.root_journal.inode)
                or current.st_uid != 0 or stat.S_IMODE(current.st_mode) != 0o700):
            raise ApplicationRuntimePreparationDenied("selected root journal identity changed")

    def _current_inputs(self, source_selection_handle: str) -> tuple[Any, Any, bytes, Any, Any, Any]:
        from .application_source_preparation import (
            RootApplicationLockReceipt,
            RootApplicationSourcePreparationSelection,
            RootPreparedApplicationSourceReceipt,
        )
        from .bootstrap_runtime_factory import (
            _APPLICATION_QUALIFICATION_NETWORK_SCOPE,
            RootApplicationQualificationConsent,
            RootSelectedApplicationQualificationChoice,
            RootApplicationSetupControllerBinding,
        )

        selection = self.source_registry.resolve_selection(source_selection_handle)
        if (type(selection) is not RootApplicationSourcePreparationSelection
                or selection.selection_handle != source_selection_handle):
            raise ApplicationRuntimePreparationDenied("source preparation selection is not current")
        source_resolver = getattr(self.source_registry, "resolve_prepared_source_for_selection", None)
        lock_resolver = getattr(self.source_registry, "resolve_current_lock_for_selection", None)
        if not callable(source_resolver) or not callable(lock_resolver):
            raise ApplicationRuntimePreparationDenied("current prepared source and lock resolver is unavailable")
        source = source_resolver(source_selection_handle)
        if (type(source) is not RootPreparedApplicationSourceReceipt
                or source.selection_handle != source_selection_handle
                or source.prepared_generation_digest != selection.prepared_generation_digest):
            raise ApplicationRuntimePreparationDenied("prepared source receipt is stale or detached")
        lock = lock_resolver(source_selection_handle, source.receipt_handle)
        lock_bytes = self.source_registry.read_current_lock_bytes(
            lock.receipt_handle, source_selection_handle, source.receipt_handle)
        lock_sha = hashlib.sha256(lock_bytes).hexdigest()
        if (type(lock) is not RootApplicationLockReceipt
                or lock.selection_handle != source_selection_handle
                or lock.prepared_source_receipt_handle != source.receipt_handle
                or lock.lock_sha256 != lock_sha):
            raise ApplicationRuntimePreparationDenied("selected lock receipt is stale or mismatched")
        consent = self.binding.resolve_application_qualification_consent(
            selection.qualification_choice_handle, _PACKAGE_PHASE_ID)
        choice_resolver = getattr(self.binding, "resolve_application_setup_choice", None)
        if not callable(choice_resolver):
            raise ApplicationRuntimePreparationDenied("current application choice resolver is unavailable")
        choice = choice_resolver(selection.qualification_choice_handle)
        if type(choice) is not RootSelectedApplicationQualificationChoice:
            raise ApplicationRuntimePreparationDenied("current application choice is not a root selection")
        now = self.monotonic()
        if (choice.selection_handle != selection.qualification_choice_handle
                or choice.setup_session_id != selection.setup_session_id
                or choice.transaction_handle != selection.transaction_handle
                or choice.plan_sha256 != selection.plan_sha256
                or choice.prepared_generation_id != selection.prepared_generation_id
                or choice.prepared_generation_digest != selection.prepared_generation_digest
                or choice.application_id != selection.application_id
                or choice.workflow_id != selection.workflow_id
                or choice.target_profile_id != selection.target_profile_id
                or choice.qualification_consent_receipt_handle
                   != selection.qualification_consent_receipt_handle
                or choice.namespace_selection_receipt_handle != selection.namespace_selection_receipt_handle
                or choice.principal_selection_receipt_handle != selection.principal_selection_receipt_handle
                or choice.controller_binding_handle != selection.controller_binding_handle
                or type(consent) is not RootApplicationQualificationConsent
                or consent.qualification_choice_handle != selection.qualification_choice_handle
                or getattr(consent, "application_id", None) != selection.application_id
                or _PACKAGE_PHASE_ID not in getattr(consent, "allowed_phase_ids", ())
                or getattr(consent, "setup_session_id", None) != selection.setup_session_id
                or consent.transaction_handle != selection.transaction_handle
                or consent.plan_sha256 != selection.plan_sha256
                or getattr(consent, "prepared_generation_id", None) != selection.prepared_generation_id
                or consent.prepared_generation_digest != selection.prepared_generation_digest
                or consent.workflow_id != selection.workflow_id
                or consent.target_profile_id != selection.target_profile_id
                or consent.namespace_selection_receipt_handle != selection.namespace_selection_receipt_handle
                or consent.principal_selection_handle != choice.principal_selection_handle
                or consent.controller_binding_handle != selection.controller_binding_handle
                or consent.principal_binding_sha256 != choice.principal_binding_sha256
                or consent.namespace_selection_handle != choice.namespace_selection_handle
                or consent.namespace_binding_sha256 != choice.namespace_binding_sha256
                or consent.network_scope != _APPLICATION_QUALIFICATION_NETWORK_SCOPE
                or consent.additional_metered_budget_usd != 0.0
                or consent.revocation_epoch != 0
                or consent.purpose != "installer-application-local-qualification"
                or getattr(consent, "expires_monotonic", 0) <= now
                or getattr(consent, "expires_monotonic", 0) > now + 30.0):
            raise ApplicationRuntimePreparationDenied("fresh package-acquisition consent is missing or mismatched")
        controller_resolver = getattr(self.binding, "resolve_application_controller_binding", None)
        if not callable(controller_resolver):
            raise ApplicationRuntimePreparationDenied("current setup controller resolver is unavailable")
        controller = controller_resolver(selection.qualification_choice_handle)
        if (type(controller) is not RootApplicationSetupControllerBinding
                or controller.handle != selection.controller_binding_handle
                or controller.setup_session_id != selection.setup_session_id
                or controller.expires_monotonic <= now
                or controller.qualification_choice_handle != selection.qualification_choice_handle):
            raise ApplicationRuntimePreparationDenied("current setup controller is stale")
        return selection, source, lock_bytes, lock, consent, controller

    @staticmethod
    def _url_is_allowed(url: str) -> bool:
        try:
            parsed = urllib.parse.urlsplit(url)
            return (parsed.scheme == "https" and parsed.hostname == "files.pythonhosted.org"
                    and parsed.port in (None, 443) and parsed.username is None
                    and parsed.password is None and not parsed.query and not parsed.fragment
                    and parsed.path.startswith("/packages/") and "\\" not in parsed.path)
        except (TypeError, ValueError):
            return False

    def _open_artifact_fd(self, artifact_sha256: str, *, expected_size: int | None = None,
                          expected_dev: int | None = None, expected_ino: int | None = None) -> int:
        if not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256):
            raise ApplicationRuntimePreparationDenied("package artifact digest is malformed")
        self._require_cas_current()
        name = f"app-runtime-package-{artifact_sha256}"
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._cas_fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_size <= 0
                or expected_size is not None and info.st_size != expected_size
                or expected_dev is not None and info.st_dev != expected_dev
                or expected_ino is not None and info.st_ino != expected_ino
                or self._hash_fd(fd, info.st_size) != artifact_sha256):
            os.close(fd)
            raise ApplicationRuntimePreparationDenied("package CAS object failed nofollow custody verification")
        return fd

    @staticmethod
    def _hash_fd(fd: int, maximum_bytes: int) -> str:
        digest = hashlib.sha256()
        offset = 0
        while offset < maximum_bytes:
            chunk = os.pread(fd, min(1024 * 1024, maximum_bytes - offset), offset)
            if not chunk:
                raise ApplicationRuntimePreparationDenied("package CAS object was truncated")
            digest.update(chunk)
            offset += len(chunk)
        return digest.hexdigest()

    def _fetch_to_cas(self, wheel: LockedPythonWheel, *, selection_handle: str,
                      lock_sha256: str, toolchain_handles: tuple[str, ...],
                      phase_consent: Any) -> tuple[int, str, int, int, int, Any]:
        if not self._url_is_allowed(wheel.url) or wheel.size_bytes > _MAX_PACKAGE_ARCHIVE_BYTES:
            raise ApplicationRuntimePreparationDenied("locked package URL or size is outside the fixed origin policy")
        if wheel.integrity_algorithm not in {"sha256", "sha512"}:
            raise ApplicationRuntimePreparationDenied("selected package lock uses unsupported integrity")
        expected_hex = wheel.integrity_digest
        width = 64 if wheel.integrity_algorithm == "sha256" else 128
        if not re.fullmatch(rf"[0-9a-f]{{{width}}}", expected_hex):
            raise ApplicationRuntimePreparationDenied("selected package integrity is malformed")
        if wheel.integrity_algorithm == "sha256":
            try:
                existing_fd = self._open_artifact_fd(expected_hex, expected_size=wheel.size_bytes)
                if self._hash_integrity_fd(existing_fd, wheel.integrity_algorithm) == expected_hex:
                    info = os.fstat(existing_fd)
                    return existing_fd, expected_hex, info.st_dev, info.st_ino, info.st_size, phase_consent
                os.close(existing_fd)
            except FileNotFoundError:
                pass
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, file_pointer, code, message, headers, new_url):
                return None

        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            NoRedirect(),
        )
        request = urllib.request.Request(
            wheel.url, method="GET",
            headers={"Accept-Encoding": "identity", "User-Agent": "hermes-installer-package-receipts/1"},
        )
        temp_name = f".pending-{secrets.token_hex(20)}"
        temp_fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=self._cas_fd)
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        total = 0
        try:
            current_selection, _source, current_lock_bytes, current_lock, current_consent, _controller = (
                self._current_inputs(selection_handle))
            if self._toolchain_receipt_handles() != toolchain_handles:
                raise ApplicationRuntimePreparationDenied(
                    "selected PM toolchain changed before the package request")
            current_wheels = select_locked_python_wheels(
                current_lock_bytes, application_id=current_selection.application_id)
            if (hashlib.sha256(current_lock_bytes).hexdigest() != lock_sha256
                    or current_lock.lock_sha256 != lock_sha256 or not current_wheels.complete
                    or not any(row == wheel for row in current_wheels.wheels)):
                raise ApplicationRuntimePreparationDenied(
                    "selected source or lock changed before the package request")
            phase_consent = current_consent
            request_started = self.monotonic()
            if (not _valid_opaque(getattr(phase_consent, "receipt_handle", None))
                    or getattr(phase_consent, "expires_monotonic", 0) <= request_started
                    or _PACKAGE_PHASE_ID not in getattr(phase_consent, "allowed_phase_ids", ())):
                raise ApplicationRuntimePreparationDenied(
                    "fresh package-acquisition phase consent expired before the package request")
            with opener.open(request, timeout=self.download_timeout) as response:
                if (response.getcode() != 200 or response.geturl() != wheel.url
                        or response.headers.get("Content-Encoding") not in (None, "identity")):
                    raise ApplicationRuntimePreparationDenied("package server response is not a direct identity GET")
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdecimal() or int(length) != wheel.size_bytes):
                    raise ApplicationRuntimePreparationDenied("package response length differs from the selected lock")
                while True:
                    chunk = response.read(min(1024 * 1024, wheel.size_bytes + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > wheel.size_bytes or total > _MAX_PACKAGE_ARCHIVE_BYTES:
                        raise ApplicationRuntimePreparationDenied("package response exceeded its locked byte bound")
                    sha256.update(chunk)
                    sha512.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(temp_fd, view)
                        view = view[written:]
            actual_integrity = sha256.hexdigest() if wheel.integrity_algorithm == "sha256" else sha512.hexdigest()
            actual_sha256 = sha256.hexdigest()
            if total != wheel.size_bytes or actual_integrity != expected_hex:
                raise ApplicationRuntimePreparationDenied("package bytes failed selected lock integrity")
            os.fsync(temp_fd)
            os.fchmod(temp_fd, 0o444)
            os.fsync(temp_fd)
            info = os.fstat(temp_fd)
            if info.st_uid != 0 or info.st_size != total or stat.S_IMODE(info.st_mode) != 0o444:
                raise ApplicationRuntimePreparationDenied("temporary package CAS object failed root custody")
            os.close(temp_fd)
            temp_fd = -1
            final_name = f"app-runtime-package-{actual_sha256}"
            try:
                os.link(temp_name, final_name, src_dir_fd=self._cas_fd, dst_dir_fd=self._cas_fd,
                        follow_symlinks=False)
            except FileExistsError:
                pass
            os.unlink(temp_name, dir_fd=self._cas_fd)
            os.fsync(self._cas_fd)
            final_fd = self._open_artifact_fd(actual_sha256, expected_size=total)
            final_info = os.fstat(final_fd)
            return (final_fd, actual_sha256, final_info.st_dev, final_info.st_ino,
                    final_info.st_size, phase_consent)
        except Exception:
            try:
                if temp_fd >= 0:
                    os.close(temp_fd)
                os.unlink(temp_name, dir_fd=self._cas_fd)
            except OSError:
                pass
            raise

    @staticmethod
    def _hash_integrity_fd(fd: int, algorithm: str) -> str:
        digest = hashlib.new(algorithm)
        size = os.fstat(fd).st_size
        offset = 0
        while offset < size:
            chunk = os.pread(fd, min(1024 * 1024, size - offset), offset)
            if not chunk:
                raise ApplicationRuntimePreparationDenied("package CAS object was truncated")
            digest.update(chunk)
            offset += len(chunk)
        return digest.hexdigest()

    def _toolchain_receipt_handles(self) -> tuple[str, ...]:
        python_resolver = getattr(self.binding, "resolve_current_pm_runtime", None)
        uv_resolver = getattr(self.binding, "resolve_current_pm_uv_tool", None)
        if not callable(python_resolver) or not callable(uv_resolver):
            raise ApplicationRuntimePreparationDenied("current PM Python/UV toolchain receipts are unavailable")
        python = python_resolver()
        uv = uv_resolver()
        machine = getattr(python, "machine", None)
        soabi = getattr(python, "soabi", None)
        version = getattr(python, "version_info", None)
        if (not isinstance(machine, str) or machine.lower() not in {"aarch64", "arm64"}
                or not isinstance(soabi, str) or "cpython-314" not in soabi
                or not isinstance(version, tuple) or len(version) < 2
                or version[:2] != (3, 14)
                or getattr(uv, "version", None) != "0.12.3"):
            raise ApplicationRuntimePreparationDenied("selected PM Python/UV receipts do not match the fixed Python 3.14 profile")
        python_handle = getattr(python, "receipt_handle", None)
        uv_handle = getattr(uv, "receipt_handle", None)
        if not _valid_opaque(python_handle) or not _valid_opaque(uv_handle):
            raise ApplicationRuntimePreparationDenied("PM toolchain receipt handle is malformed")
        return (python_handle, uv_handle)

    def _build_artifact_observation(self, selection: Any, source: Any, lock: Any,
                                    consent: Any, controller: Any, wheel: LockedPythonWheel,
                                    fd: int, digest: str, device: int, inode: int,
                                    size_bytes: int) -> RootApplicationLockedPackageArtifactReceipt:
        receipt_handle = secrets.token_urlsafe(36)
        now = self.monotonic()
        expiry = min(now + self.ttl_seconds, selection.expires_monotonic,
                     source.expires_monotonic, lock.expires_monotonic,
                     controller.expires_monotonic)
        if expiry <= now:
            raise ApplicationRuntimePreparationDenied("package artifact evidence lease is already expired")
        observation = RootApplicationLockedPackageArtifactReceipt(
            receipt_handle=receipt_handle,
            artifact_id=f"app-runtime-package-{digest}",
            application_id=selection.application_id,
            source_preparation_selection_handle=selection.selection_handle,
            qualification_choice_handle=selection.qualification_choice_handle,
            qualification_consent_receipt_handle=consent.receipt_handle,
            setup_session_id=selection.setup_session_id,
            transaction_handle=selection.transaction_handle,
            plan_sha256=selection.plan_sha256,
            prepared_generation_digest=selection.prepared_generation_digest,
            lock_receipt_handle=lock.receipt_handle,
            lock_sha256=lock.lock_sha256,
            lock_member_id=lock.lock_member_path,
            package_name=wheel.package_name,
            package_version=wheel.package_version,
            artifact_kind="wheel",
            platform_tags=(wheel.selected_tag,),
            origin_policy_id=_PACKAGE_ORIGIN_POLICY_ID,
            source_url=wheel.url,
            lock_integrity_algorithm=wheel.integrity_algorithm,
            lock_integrity_digest=wheel.integrity_digest,
            artifact_sha256=digest,
            size_bytes=size_bytes,
            cas_device=device,
            cas_inode=inode,
            cas_mode=0o444,
            controller_binding_handle=selection.controller_binding_handle,
            issued_monotonic=now,
            expires_monotonic=expiry,
            signature="",
        )
        self._pending_artifacts[receipt_handle] = observation
        # The AuthorityService retains the signed receipt synchronously from
        # inside issue_locked_package_artifact. Install the exact pending CAS
        # FD first so that retention can bind the signature to its inode.
        self._artifact_entries[receipt_handle] = _PackageArtifactEntry(
            observation, None, fd, consent)
        try:
            signed = self.signer.issue_locked_package_artifact(observation)
        except Exception:
            self._pending_artifacts.pop(receipt_handle, None)
            entry = self._artifact_entries.pop(receipt_handle, None)
            if entry is not None and entry.fd >= 0:
                os.close(entry.fd)
            raise ApplicationRuntimePreparationDenied("AuthorityService rejected locked package observation") from None
        if (type(signed) is not RootApplicationLockedPackageArtifactReceipt
                or signed.claims() != observation.claims()
                or not isinstance(signed.signature, str) or not signed.signature
                or self._artifact_entries[receipt_handle].receipt != signed):
            self._pending_artifacts.pop(receipt_handle, None)
            entry = self._artifact_entries.pop(receipt_handle, None)
            if entry is not None and entry.fd >= 0:
                os.close(entry.fd)
            raise ApplicationRuntimePreparationDenied("AuthorityService returned a malformed package receipt")
        self._pending_artifacts.pop(receipt_handle, None)
        return signed

    def _build_license_observation(self, artifact: RootApplicationLockedPackageArtifactReceipt,
                                   evidence: PythonPackageLicenseEvidence) -> RootApplicationPackageLicenseObservation:
        now = self.monotonic()
        expiry = min(artifact.expires_monotonic, now + self.ttl_seconds)
        observation = RootApplicationPackageLicenseObservation(
            receipt_handle=secrets.token_urlsafe(36),
            artifact_receipt_handle=artifact.receipt_handle,
            artifact_sha256=artifact.artifact_sha256,
            package_name=artifact.package_name,
            package_version=artifact.package_version,
            metadata_kind=evidence.metadata_kind,
            metadata_member_path=evidence.metadata_member_path,
            metadata_member_sha256=evidence.metadata_member_sha256,
            declared_license_expression=evidence.declared_license_expression,
            license_member_records=tuple(
                _FrozenClaimMap(path=path, sha256=digest, size_bytes=size)
                for path, digest, size in evidence.license_member_records
            ),
            evidence_sha256=evidence.evidence_sha256,
            eligibility=evidence.eligibility,
            review_policy_receipt_handle=None,
            issued_monotonic=now,
            expires_monotonic=expiry,
            signature="",
        )
        self._pending_licenses[observation.receipt_handle] = observation
        self._license_entries[observation.receipt_handle] = _PackageLicenseEntry(
            observation, None, artifact.receipt_handle)
        try:
            signed = self.signer.issue_package_license_observation(observation)
        except Exception:
            self._pending_licenses.pop(observation.receipt_handle, None)
            self._license_entries.pop(observation.receipt_handle, None)
            raise ApplicationRuntimePreparationDenied("AuthorityService rejected package license observation") from None
        if (type(signed) is not RootApplicationPackageLicenseObservation
                or signed.claims() != observation.claims()
                or not signed.signature
                or self._license_entries[observation.receipt_handle].receipt != signed):
            self._pending_licenses.pop(observation.receipt_handle, None)
            self._license_entries.pop(observation.receipt_handle, None)
            raise ApplicationRuntimePreparationDenied("AuthorityService returned a malformed license receipt")
        self._pending_licenses.pop(observation.receipt_handle, None)
        return signed

    def prepare_selected_packages(
        self, source_preparation_selection_handle: str,
    ) -> RootApplicationOfflinePackageClosureReceipt:
        """Acquire one exact current Python lock closure after same-choice phase consent."""
        if not _valid_opaque(source_preparation_selection_handle):
            raise ApplicationRuntimePreparationDenied("source preparation handle is malformed")
        selection, source, lock_bytes, lock, consent, controller = self._current_inputs(
            source_preparation_selection_handle)
        if selection.application_id not in _PYTHON_LOCK_APPS:
            raise ApplicationRuntimePreparationDenied("application has no approved Python package acquisition profile")
        wheels = select_locked_python_wheels(lock_bytes, application_id=selection.application_id)
        if not wheels.complete:
            raise ApplicationRuntimePreparationDenied(
                "selected platform lock closure has unresolved wheel blockers: " + ",".join(wheels.blockers))
        total_locked_bytes = sum(row.size_bytes for row in wheels.wheels)
        if not wheels.wheels or total_locked_bytes > _MAX_PACKAGE_ARCHIVE_BYTES:
            raise ApplicationRuntimePreparationDenied("selected lock closure is empty or exceeds the aggregate package bound")
        toolchain_handles = self._toolchain_receipt_handles()
        records: list[RootApplicationOfflinePackageRecord] = []
        artifact_handles: list[str] = []
        license_handles: list[str] = []
        for wheel in wheels.wheels:
            # Resolve consent, source, lock, controller and toolchain again
            # immediately before every package GET; no user URL enters here.
            selection, source, current_lock_bytes, lock, consent, controller = self._current_inputs(
                source_preparation_selection_handle)
            if (hashlib.sha256(current_lock_bytes).hexdigest() != wheels.lock_sha256
                    or lock.lock_sha256 != wheels.lock_sha256):
                raise ApplicationRuntimePreparationDenied("selected lock changed during package acquisition")
            current_toolchain = self._toolchain_receipt_handles()
            if current_toolchain != toolchain_handles:
                raise ApplicationRuntimePreparationDenied("selected PM toolchain changed during package acquisition")
            self._require_cas_current()
            try:
                fd, digest, device, inode, size, acquisition_consent = self._fetch_to_cas(
                    wheel, selection_handle=source_preparation_selection_handle,
                    lock_sha256=wheels.lock_sha256, toolchain_handles=toolchain_handles,
                    phase_consent=consent)
            except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                raise ApplicationRuntimePreparationDenied("fixed locked package acquisition failed") from None
            artifact = self._build_artifact_observation(
                selection, source, lock, acquisition_consent, controller, wheel,
                fd, digest, device, inode, size)
            try:
                with os.fdopen(os.dup(fd), "rb") as stream:
                    evidence = observe_python_wheel_license(
                        stream, expected_artifact_sha256=artifact.artifact_sha256,
                        expected_package_name=wheel.package_name,
                        expected_package_version=wheel.package_version)
                license_receipt = self._build_license_observation(artifact, evidence)
            except Exception:
                raise ApplicationRuntimePreparationDenied(
                    f"selected package license evidence is unavailable for {wheel.package_name}") from None
            artifact_handles.append(artifact.receipt_handle)
            license_handles.append(license_receipt.receipt_handle)
            records.append(RootApplicationOfflinePackageRecord(
                wheel.package_name, wheel.package_version, lock.lock_member_path,
                wheel.integrity_algorithm, wheel.integrity_digest, artifact.receipt_handle,
                artifact.artifact_sha256, artifact.size_bytes, "wheel", (wheel.selected_tag,),
                license_receipt.receipt_handle,
            ))
        selection, source, current_lock_bytes, lock, consent, controller = self._current_inputs(
            source_preparation_selection_handle)
        if hashlib.sha256(current_lock_bytes).hexdigest() != wheels.lock_sha256:
            raise ApplicationRuntimePreparationDenied("selected lock changed before package closure issuance")
        records_tuple = tuple(sorted(records, key=lambda item: (item.package_name, item.package_version)))
        record_wire = [
            {name: getattr(row, name) for name in row.__dataclass_fields__}
            for row in records_tuple
        ]
        closure_sha = hashlib.sha256(json.dumps(
            record_wire, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")).hexdigest()
        now = self.monotonic()
        expiry = min(now + self.ttl_seconds, selection.expires_monotonic,
                     source.expires_monotonic, lock.expires_monotonic,
                     controller.expires_monotonic,
                     *(self._artifact_entries[item].receipt.expires_monotonic
                       for item in artifact_handles
                       if self._artifact_entries[item].receipt is not None))
        closure = RootApplicationOfflinePackageClosureReceipt(
            secrets.token_urlsafe(36), selection.selection_handle,
            selection.setup_session_id, selection.transaction_handle,
            selection.prepared_generation_digest, selection.application_id,
            source.receipt_handle, lock.receipt_handle, lock.lock_sha256,
            "linux-aarch64-glibc2.36-python3.14", toolchain_handles,
            records_tuple, closure_sha, now, expiry)
        if expiry <= now:
            raise ApplicationRuntimePreparationDenied("package closure lease expired before issuance")
        self._closure_entries[closure.receipt_handle] = _PackageClosureEntry(
            selection, closure, tuple(artifact_handles), tuple(license_handles))
        return closure

    def resolve_selected_packages(
        self, receipt_handle: str, source_preparation_selection_handle: str,
    ) -> RootApplicationOfflinePackageClosureReceipt:
        entry = self._closure_entries.get(receipt_handle)
        if (entry is None or entry.receipt.expires_monotonic <= self.monotonic()
                or entry.selection.selection_handle != source_preparation_selection_handle):
            raise ApplicationRuntimePreparationDenied("package closure receipt is absent, stale, or detached")
        selection, source, lock_bytes, lock, _consent, _controller = self._current_inputs(
            source_preparation_selection_handle)
        receipt = entry.receipt
        if (selection != entry.selection or source.receipt_handle != receipt.source_receipt_handle
                or lock.receipt_handle != receipt.lock_receipt_handle
                or hashlib.sha256(lock_bytes).hexdigest() != receipt.lock_sha256
                or selection.application_id != receipt.application_id
                or tuple(self._toolchain_receipt_handles()) != receipt.runtime_toolchain_receipt_handles):
            raise ApplicationRuntimePreparationDenied("package closure no longer matches current source, lock or toolchain")
        for artifact_handle, license_handle in zip(entry.artifact_handles, entry.license_handles):
            artifact = self._artifact_entries.get(artifact_handle)
            license_entry = self._license_entries.get(license_handle)
            if (artifact is None or artifact.receipt is None or license_entry is None
                    or license_entry.receipt is None
                    or not self.verify_observation_receipt(artifact.receipt)
                    or not self.verify_observation_receipt(license_entry.receipt)):
                raise ApplicationRuntimePreparationDenied("package closure contains a stale artifact or license observation")
        return receipt

    def resolve_package_artifact(self, receipt_handle: str,
                                 source_preparation_selection_handle: str,
                                 closure_receipt_handle: str) -> tuple[RootApplicationLockedPackageArtifactReceipt, int]:
        closure = self.resolve_selected_packages(closure_receipt_handle, source_preparation_selection_handle)
        if not any(row.artifact_receipt_handle == receipt_handle for row in closure.package_records):
            raise ApplicationRuntimePreparationDenied("package artifact is not a member of this closure")
        entry = self._artifact_entries.get(receipt_handle)
        if (entry is None or entry.receipt is None or not self.verify_observation_receipt(entry.receipt)):
            raise ApplicationRuntimePreparationDenied("package artifact receipt is not current")
        fd = self._open_artifact_fd(entry.receipt.artifact_sha256,
                                    expected_size=entry.receipt.size_bytes,
                                    expected_dev=entry.receipt.cas_device,
                                    expected_ino=entry.receipt.cas_inode)
        return entry.receipt, fd

    def resolve_package_license(self, receipt_handle: str,
                                artifact_receipt_handle: str,
                                source_preparation_selection_handle: str,
                                closure_receipt_handle: str) -> RootApplicationPackageLicenseObservation:
        closure = self.resolve_selected_packages(closure_receipt_handle, source_preparation_selection_handle)
        matching = next((row for row in closure.package_records
                         if row.artifact_receipt_handle == artifact_receipt_handle
                         and row.license_receipt_handle == receipt_handle), None)
        entry = self._license_entries.get(receipt_handle)
        if (matching is None or entry is None or entry.receipt is None
                or entry.artifact_receipt_handle != artifact_receipt_handle
                or not self.verify_observation_receipt(entry.receipt)):
            raise ApplicationRuntimePreparationDenied("package license observation is not current closure evidence")
        return entry.receipt

    def verify_observation_for_authority(self, kind: str, observation: Any) -> bool:
        if kind == "locked-package-artifact":
            expected = self._pending_artifacts.get(getattr(observation, "receipt_handle", ""))
            if type(observation) is not RootApplicationLockedPackageArtifactReceipt or observation is not expected:
                return False
            try:
                self._verify_artifact_observation(observation)
                return True
            except Exception:
                return False
        if kind == "package-license":
            expected = self._pending_licenses.get(getattr(observation, "receipt_handle", ""))
            if type(observation) is not RootApplicationPackageLicenseObservation or observation is not expected:
                return False
            try:
                self._verify_license_observation(observation)
                return True
            except Exception:
                return False
        return False

    def retain_authority_signed_observation(self, kind: str, receipt: Any) -> bool:
        if type(receipt) is RootApplicationLockedPackageArtifactReceipt and kind == "locked-package-artifact":
            expected = self._pending_artifacts.get(receipt.receipt_handle)
            if expected is None or receipt.claims() != expected.claims() or not receipt.signature:
                return False
            try:
                self._verify_artifact_observation(receipt)
            except Exception:
                return False
            entry = self._artifact_entries.get(receipt.receipt_handle)
            if entry is None or entry.fd < 0:
                return False
            entry.receipt = receipt
            return True
        if type(receipt) is RootApplicationPackageLicenseObservation and kind == "package-license":
            expected = self._pending_licenses.get(receipt.receipt_handle)
            if expected is None or receipt.claims() != expected.claims() or not receipt.signature:
                return False
            try:
                self._verify_license_observation(receipt)
            except Exception:
                return False
            entry = self._license_entries.get(receipt.receipt_handle)
            if entry is None or entry.artifact_receipt_handle != receipt.artifact_receipt_handle:
                return False
            entry.receipt = receipt
            return True
        return False

    def verify_observation_receipt(self, receipt: Any) -> bool:
        if type(receipt) is RootApplicationLockedPackageArtifactReceipt:
            entry = self._artifact_entries.get(receipt.receipt_handle)
            if entry is None or entry.receipt is None or entry.receipt != receipt:
                return False
            try:
                self._verify_artifact_observation(receipt)
                self.authority_service._verify_root_selected_signature(
                    _PACKAGE_ARTIFACT_DOMAIN, receipt.claims(), receipt.signature)
                return True
            except Exception:
                return False
        if type(receipt) is RootApplicationPackageLicenseObservation:
            entry = self._license_entries.get(receipt.receipt_handle)
            if entry is None or entry.receipt is None or entry.receipt != receipt:
                return False
            try:
                self._verify_license_observation(receipt)
                self.authority_service._verify_root_selected_signature(
                    _PACKAGE_LICENSE_DOMAIN, receipt.claims(), receipt.signature)
                return True
            except Exception:
                return False
        return False

    def _verify_artifact_observation(self, receipt: RootApplicationLockedPackageArtifactReceipt) -> None:
        selection, source, lock_bytes, lock, consent, controller = self._current_inputs(
            receipt.source_preparation_selection_handle)
        artifact_entry = self._artifact_entries.get(receipt.receipt_handle)
        phase_consent = artifact_entry.phase_consent if artifact_entry is not None else None
        locked_selection = select_locked_python_wheels(
            lock_bytes, application_id=selection.application_id)
        expected = [row for row in locked_selection.wheels
                    if row.package_name == receipt.package_name
                    and row.package_version == receipt.package_version]
        if (receipt.application_id != selection.application_id
                or receipt.qualification_choice_handle != selection.qualification_choice_handle
                or phase_consent is None
                or receipt.qualification_consent_receipt_handle != phase_consent.receipt_handle
                or phase_consent.qualification_choice_handle != selection.qualification_choice_handle
                or phase_consent.setup_session_id != selection.setup_session_id
                or phase_consent.transaction_handle != selection.transaction_handle
                or _PACKAGE_PHASE_ID not in phase_consent.allowed_phase_ids
                or phase_consent.issued_monotonic > receipt.issued_monotonic
                or receipt.setup_session_id != selection.setup_session_id
                or receipt.transaction_handle != selection.transaction_handle
                or receipt.plan_sha256 != selection.plan_sha256
                or receipt.prepared_generation_digest != selection.prepared_generation_digest
                or receipt.lock_receipt_handle != lock.receipt_handle
                or receipt.lock_sha256 != lock.lock_sha256
                or receipt.lock_member_id != lock.lock_member_path
                or receipt.controller_binding_handle != controller.handle
                or receipt.origin_policy_id != _PACKAGE_ORIGIN_POLICY_ID
                or not self._url_is_allowed(receipt.source_url)
                or receipt.artifact_kind != "wheel"
                or not locked_selection.complete or len(expected) != 1
                or receipt.source_url != expected[0].url
                or receipt.lock_integrity_algorithm != expected[0].integrity_algorithm
                or receipt.lock_integrity_digest != expected[0].integrity_digest
                or receipt.size_bytes != expected[0].size_bytes
                or receipt.platform_tags != (expected[0].selected_tag,)
                or receipt.artifact_id != f"app-runtime-package-{receipt.artifact_sha256}"
                or receipt.expires_monotonic <= self.monotonic()):
            raise ApplicationRuntimePreparationDenied("locked package observation no longer matches current setup selection")
        self._require_cas_current()
        fd = self._open_artifact_fd(receipt.artifact_sha256, expected_size=receipt.size_bytes,
                                    expected_dev=receipt.cas_device, expected_ino=receipt.cas_inode)
        try:
            if self._hash_integrity_fd(fd, expected[0].integrity_algorithm) != expected[0].integrity_digest:
                raise ApplicationRuntimePreparationDenied("package bytes no longer match selected lock integrity")
        finally:
            os.close(fd)
        if hashlib.sha256(lock_bytes).hexdigest() != receipt.lock_sha256:
            raise ApplicationRuntimePreparationDenied("locked package observation lock bytes changed")

    def _verify_license_observation(self, receipt: RootApplicationPackageLicenseObservation) -> None:
        artifact_entry = self._artifact_entries.get(receipt.artifact_receipt_handle)
        if (artifact_entry is None or artifact_entry.receipt is None
                or artifact_entry.receipt.artifact_sha256 != receipt.artifact_sha256
                or artifact_entry.receipt.package_name != receipt.package_name
                or artifact_entry.receipt.package_version != receipt.package_version
                or receipt.expires_monotonic <= self.monotonic()):
            raise ApplicationRuntimePreparationDenied("license observation is detached from its locked package")
        self._verify_artifact_observation(artifact_entry.receipt)
        fd = self._open_artifact_fd(receipt.artifact_sha256,
                                    expected_size=artifact_entry.receipt.size_bytes,
                                    expected_dev=artifact_entry.receipt.cas_device,
                                    expected_ino=artifact_entry.receipt.cas_inode)
        try:
            with os.fdopen(os.dup(fd), "rb") as stream:
                evidence = observe_python_wheel_license(
                    stream, expected_artifact_sha256=receipt.artifact_sha256,
                    expected_package_name=receipt.package_name,
                    expected_package_version=receipt.package_version)
        finally:
            os.close(fd)
        records = tuple({"path": path, "sha256": digest, "size_bytes": size}
                        for path, digest, size in evidence.license_member_records)
        if (receipt.metadata_kind != evidence.metadata_kind
                or receipt.metadata_member_path != evidence.metadata_member_path
                or receipt.metadata_member_sha256 != evidence.metadata_member_sha256
                or receipt.declared_license_expression != evidence.declared_license_expression
                or tuple(dict(row) for row in receipt.license_member_records) != records
                or receipt.evidence_sha256 != evidence.evidence_sha256
                or receipt.eligibility != evidence.eligibility
                or receipt.review_policy_receipt_handle is not None):
            raise ApplicationRuntimePreparationDenied("license observation differs from actual wheel members")


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationBuildBackendArtifactReceipt:
    schema: int
    receipt_handle: str
    artifact_id: str
    package_name: str
    package_version: str
    filename: str
    sha256: str
    size_bytes: int
    source_url_sha256: str
    metadata_sha256: str
    license_observation_handle: str
    backend_manifest_artifact_id: str
    backend_manifest_sha256: str
    backend_manifest_receipt_handle: str
    pyproject_receipt_handle: str
    source_preparation_selection_handle: str
    qualification_choice_handle: str
    target_platform: str
    python_abi: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _BACKEND_RECEIPT_SEAL:
            raise TypeError("backend package receipts are minted by the root backend registry")


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationBuildBackendClosureReceipt:
    schema: int
    receipt_handle: str
    application_id: str
    build_backend: str
    backend_requirement_sha256: str
    backend_manifest_artifact_id: str
    backend_manifest_sha256: str
    backend_manifest_receipt_handle: str
    pyproject_receipt_handle: str
    source_preparation_selection_handle: str
    qualification_choice_handle: str
    package_artifact_receipt_handles: tuple[str, ...]
    license_observation_handles: tuple[str, ...]
    backend_closure_sha256: str
    target_platform: str
    python_abi: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _BACKEND_RECEIPT_SEAL:
            raise TypeError("backend package closures are minted by the root backend registry")


_BACKEND_RECEIPT_SEAL = object()
_BACKEND_POLICY_ARTIFACT_ID = "installer-application-pep517-backend-sources-v1"
_BACKEND_POLICY_SHA256 = "c7d64c6ca0a186437d32b8093df0be0a3dc660fc721172e7ce1a56fd5a87c623"
_BACKEND_TARGET_PLATFORM = "linux-aarch64-glibc2.36-python3.14"
_BACKEND_PYTHON_ABI = "cp314-cp314-manylinux_2_36_aarch64"
_BACKEND_PACKAGES: Mapping[str, tuple[tuple[str, str], ...]] = {
    "graphify": (("setuptools", "84.0.0"),),
    "browser-use": (
        ("hatchling", "1.32.0"), ("packaging", "26.3"),
        ("pathspec", "1.1.1"), ("pluggy", "1.6.0"),
        ("tomlkit", "0.15.1"), ("trove-classifiers", "2026.9.21.13"),
    ),
    "scrapegraph-ai": (
        ("hatchling", "1.26.3"), ("packaging", "26.3"),
        ("pathspec", "1.1.1"), ("pluggy", "1.6.0"),
        ("trove-classifiers", "2026.9.21.13"),
    ),
}


@dataclass(slots=True)
class _BackendClosureEntry:
    input_selection: Any
    receipt: RootApplicationBuildBackendClosureReceipt
    artifacts: tuple[RootApplicationBuildBackendArtifactReceipt, ...]
    source_observations: tuple[Any, ...]
    license_observations: tuple[Any, ...]


class RootApplicationBuildBackendClosureRegistry:
    """Retain a separate PEP 517 wheel closure for one selected Python app.

    Wheel bytes and license records come only from the finite v152 source table
    through the separately typed v157 observer. Runtime-lock package receipts
    are never reused or relabelled as build dependencies.
    """

    def __init__(self, *, selected_installation_binding: Any,
                 source_preparation_registry: Any, backend_source_observer: Any,
                 root_journal: RootJournalSelection, setup_choice_registry: Any,
                 monotonic=time.monotonic, ttl_seconds: float = 900.0) -> None:
        if (os.geteuid() != 0 or type(root_journal) is not RootJournalSelection
                or not callable(getattr(selected_installation_binding,
                                       "resolve_application_runtime_preparation_input_selection", None))
                or not callable(getattr(source_preparation_registry, "resolve_selection", None))
                or not callable(getattr(source_preparation_registry,
                                       "resolve_current_prepared_source_for_selection", None))
                or not callable(getattr(source_preparation_registry,
                                       "resolve_current_lock_for_selection", None))
                or not callable(getattr(source_preparation_registry, "read_current_source_members", None))
                or not callable(getattr(setup_choice_registry,
                                       "resolve_application_qualification_consent", None))
                or not callable(getattr(backend_source_observer,
                                       "observe_selected_backend_source", None))
                or not callable(getattr(backend_source_observer, "verify_current", None))
                or not callable(getattr(backend_source_observer,
                                       "observe_embedded_backend_licenses", None))
                or not callable(getattr(backend_source_observer, "open_blob", None))
                or not 0 < ttl_seconds <= 1800):
            raise ValueError("root PEP 517 backend closure bindings are unavailable")
        self.binding = selected_installation_binding
        self.source_registry = source_preparation_registry
        self.backend_source_observer = backend_source_observer
        self.root_journal = root_journal
        self.setup_choice_registry = setup_choice_registry
        self.monotonic = monotonic
        self.ttl_seconds = float(ttl_seconds)
        self._entries: dict[str, _BackendClosureEntry] = {}
        self._inputs: dict[str, Any] = {}

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        source_preparation_registry: Any,
                        backend_source_observer: Any,
                        root_journal: RootJournalSelection,
                        setup_choice_registry: Any | None = None,
                        **kwargs: Any) -> "RootApplicationBuildBackendClosureRegistry":
        registry = cls(
            selected_installation_binding=selected_installation_binding,
            source_preparation_registry=source_preparation_registry,
            backend_source_observer=backend_source_observer,
            root_journal=root_journal,
            setup_choice_registry=setup_choice_registry or selected_installation_binding,
            **kwargs)
        attach = getattr(selected_installation_binding,
                         "attach_application_backend_closure_registry", None)
        if not callable(attach):
            raise ValueError("root setup binding has no typed PEP 517 closure attachment")
        attach(registry)
        return registry

    def _current_inputs(self, input_selection_handle: str) -> tuple[Any, Any, Any, Any, Any]:
        from .application_runtime_selection import RootApplicationRuntimePreparationInputSelection
        if not _valid_opaque(input_selection_handle):
            raise ApplicationRuntimePreparationDenied("runtime input selection handle is malformed")
        try:
            inputs = self.binding.resolve_application_runtime_preparation_input_selection(
                input_selection_handle)
            if (type(inputs) is not RootApplicationRuntimePreparationInputSelection
                    or inputs.selection_handle != input_selection_handle
                    or inputs.runtime_kind != "python"
                    or inputs.application_id not in _BACKEND_PACKAGES
                    or inputs.expires_monotonic <= self.monotonic()):
                raise ValueError
            source_selection = self.source_registry.resolve_selection(
                inputs.source_preparation_selection_handle)
            source = self.source_registry.resolve_current_prepared_source_for_selection(
                inputs.source_preparation_selection_handle)
            lock = self.source_registry.resolve_current_lock_for_selection(
                inputs.source_preparation_selection_handle, source.receipt_handle)
            pyproject = self.source_registry.read_current_source_members(
                inputs.source_preparation_selection_handle, source.receipt_handle,
                ("pyproject.toml",)).get("pyproject.toml")
            lock_bytes = self.source_registry.read_current_lock_bytes(
                lock.receipt_handle, inputs.source_preparation_selection_handle,
                source.receipt_handle)
            if (source_selection.application_id != inputs.application_id
                    or source.receipt_handle != inputs.prepared_source_receipt_handle
                    or source.source_generation_manifest_sha256
                       != inputs.source_generation_manifest_sha256
                    or lock.receipt_handle != inputs.selected_lock_receipt_handle
                    or lock.lock_sha256 != inputs.lock_sha256
                    or hashlib.sha256(lock_bytes).hexdigest() != inputs.lock_sha256
                    or not isinstance(pyproject, bytes)):
                raise ValueError
            backend = inspect_application_build_backend(inputs.application_id, pyproject)
            consent = self.setup_choice_registry.resolve_application_qualification_consent(
                inputs.qualification_choice_handle, "acquire-locked-runtime-packages")
            controller = self.binding.resolve_application_controller_binding(
                inputs.qualification_choice_handle)
            if (getattr(consent, "qualification_choice_handle", None)
                    != inputs.qualification_choice_handle
                    or getattr(consent, "application_id", None) != inputs.application_id
                    or "acquire-locked-runtime-packages"
                       not in getattr(consent, "allowed_phase_ids", ())
                    or getattr(consent, "additional_metered_budget_usd", None) != 0.0
                    or getattr(consent, "expires_monotonic", 0) <= self.monotonic()
                    or getattr(controller, "handle", None) != inputs.controller_binding_handle
                    or getattr(controller, "expires_monotonic", 0) <= self.monotonic()
                    or not self.binding.verify_application_controller_binding(controller)):
                raise ValueError
            return inputs, source, lock, backend, consent
        except ApplicationRuntimePreparationDenied:
            raise
        except Exception:
            raise ApplicationRuntimePreparationDenied(
                "current source, lock, choice, controller or project backend is unavailable") from None

    def prepare_selected_backend(
        self, preparation_input_selection_handle: str,
    ) -> RootApplicationBuildBackendClosureReceipt:
        inputs, source, lock, backend, _consent = self._current_inputs(
            preparation_input_selection_handle)
        expected_packages = _BACKEND_PACKAGES[inputs.application_id]
        observed_sources: list[Any] = []
        observed_licenses: list[Any] = []
        artifacts: list[RootApplicationBuildBackendArtifactReceipt] = []
        policy_receipt_handle: str | None = None
        now = self.monotonic()
        expiry = min(now + self.ttl_seconds, inputs.expires_monotonic,
                     source.expires_monotonic, lock.expires_monotonic)
        for package_name, package_version in expected_packages:
            current, current_source, current_lock, current_backend, _consent = self._current_inputs(
                preparation_input_selection_handle)
            if (current != inputs or current_source.receipt_handle != source.receipt_handle
                    or current_lock.lock_sha256 != lock.lock_sha256
                    or current_backend != backend):
                raise ApplicationRuntimePreparationDenied(
                    "application source, lock or build backend changed during package acquisition")
            try:
                observation = self.backend_source_observer.observe_selected_backend_source(
                    preparation_input_selection_handle, package_name)
                license_observation = self.backend_source_observer.observe_embedded_backend_licenses(
                    observation, preparation_input_selection_handle)
                if (getattr(observation, "policy_artifact_id", None) != _BACKEND_POLICY_ARTIFACT_ID
                        or getattr(observation, "policy_sha256", None) != _BACKEND_POLICY_SHA256
                        or getattr(observation, "preparation_input_selection_handle", None)
                           != preparation_input_selection_handle
                        or getattr(observation, "source_preparation_receipt_handle", None)
                           != source.receipt_handle
                        or getattr(observation, "pyproject_receipt_handle", None)
                           != source.receipt_handle
                        or getattr(observation, "qualification_choice_handle", None)
                           != inputs.qualification_choice_handle
                        or getattr(observation, "package_name", None) != package_name
                        or getattr(observation, "package_version", None) != package_version
                        or getattr(license_observation, "license_observation_handle", None)
                           != getattr(observation, "license_observation_handle", None)
                        or not self.backend_source_observer.verify_current(
                            observation, preparation_input_selection_handle)):
                    raise ValueError
                policy_handle = getattr(observation, "policy_member_receipt_handle", None)
                if (not _valid_opaque(policy_handle)
                        or policy_receipt_handle not in (None, policy_handle)):
                    raise ValueError
                policy_receipt_handle = policy_handle
                source_handle = getattr(observation, "source_observation_handle", None)
                license_handle = getattr(license_observation, "license_observation_handle", None)
                source_url_sha = getattr(observation, "source_url_sha256", None)
                digest = getattr(observation, "sha256", None)
                metadata_sha = getattr(observation, "metadata_sha256", None)
                size_bytes = getattr(observation, "size_bytes", None)
                if (not _valid_opaque(source_handle) or not _valid_opaque(license_handle)
                        or not all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item)
                                   for item in (source_url_sha, digest, metadata_sha))
                        or type(size_bytes) is not int or not 0 < size_bytes <= 1024 * 1024
                        or getattr(observation, "expires_monotonic", 0) <= now
                        or getattr(license_observation, "expires_monotonic", 0) <= now):
                    raise ValueError
                expiry = min(expiry, observation.expires_monotonic,
                             license_observation.expires_monotonic)
                observed_sources.append(observation)
                observed_licenses.append(license_observation)
                artifact_id = f"application-backend-wheel-{package_name}-{package_version}"
                artifacts.append(RootApplicationBuildBackendArtifactReceipt(
                    schema=1, receipt_handle=secrets.token_urlsafe(36),
                    artifact_id=artifact_id, package_name=package_name,
                    package_version=package_version,
                    filename=getattr(observation, "filename"), sha256=digest,
                    size_bytes=size_bytes, source_url_sha256=source_url_sha,
                    metadata_sha256=metadata_sha, license_observation_handle=license_handle,
                    backend_manifest_artifact_id=_BACKEND_POLICY_ARTIFACT_ID,
                    backend_manifest_sha256=_BACKEND_POLICY_SHA256,
                    backend_manifest_receipt_handle=policy_handle,
                    pyproject_receipt_handle=source.receipt_handle,
                    source_preparation_selection_handle=inputs.source_preparation_selection_handle,
                    qualification_choice_handle=inputs.qualification_choice_handle,
                    target_platform=_BACKEND_TARGET_PLATFORM, python_abi=_BACKEND_PYTHON_ABI,
                    issued_monotonic=now, expires_monotonic=expiry,
                    _seal=_BACKEND_RECEIPT_SEAL))
            except ApplicationRuntimePreparationDenied:
                raise
            except Exception:
                raise ApplicationRuntimePreparationDenied(
                    f"selected PEP 517 backend package {package_name} is not currently held and verified") from None
        if not policy_receipt_handle or not artifacts or expiry <= now:
            raise ApplicationRuntimePreparationDenied("backend source closure is empty or expired")
        req_digest = hashlib.sha256(_canonical({
            "application_id": inputs.application_id,
            "backend": backend.backend,
            "requirements": backend.requirements,
        })).hexdigest()
        package_rows = [
            {"artifact_id": row.artifact_id, "package_name": row.package_name,
             "package_version": row.package_version, "sha256": row.sha256,
             "size_bytes": row.size_bytes, "source_url_sha256": row.source_url_sha256,
             "metadata_sha256": row.metadata_sha256,
             "license_observation_handle": row.license_observation_handle,
             "license_evidence_sha256": license.evidence_sha256,
             "license_member_records": [list(item) for item in license.license_member_records],
             "declared_license_expression": license.declared_license_expression,
             "eligibility": license.eligibility}
            for row, license in zip(artifacts, observed_licenses)
        ]
        closure_digest = hashlib.sha256(_canonical({
            "application_id": inputs.application_id,
            "build_backend": backend.backend,
            "backend_requirement_sha256": req_digest,
            "backend_manifest_artifact_id": _BACKEND_POLICY_ARTIFACT_ID,
            "backend_manifest_sha256": _BACKEND_POLICY_SHA256,
            "pyproject_receipt_handle": source.receipt_handle,
            "package_rows": package_rows,
        })).hexdigest()
        closure = RootApplicationBuildBackendClosureReceipt(
            schema=1, receipt_handle=secrets.token_urlsafe(36),
            application_id=inputs.application_id, build_backend=backend.backend,
            backend_requirement_sha256=req_digest,
            backend_manifest_artifact_id=_BACKEND_POLICY_ARTIFACT_ID,
            backend_manifest_sha256=_BACKEND_POLICY_SHA256,
            backend_manifest_receipt_handle=policy_receipt_handle,
            pyproject_receipt_handle=source.receipt_handle,
            source_preparation_selection_handle=inputs.source_preparation_selection_handle,
            qualification_choice_handle=inputs.qualification_choice_handle,
            package_artifact_receipt_handles=tuple(row.receipt_handle for row in artifacts),
            license_observation_handles=tuple(row.license_observation_handle for row in artifacts),
            backend_closure_sha256=closure_digest,
            target_platform=_BACKEND_TARGET_PLATFORM, python_abi=_BACKEND_PYTHON_ABI,
            issued_monotonic=now, expires_monotonic=expiry, _seal=_BACKEND_RECEIPT_SEAL)
        if closure.receipt_handle in self._entries:
            raise ApplicationRuntimePreparationDenied("backend closure receipt handle collision")
        self._inputs[preparation_input_selection_handle] = inputs
        self._entries[closure.receipt_handle] = _BackendClosureEntry(
            inputs, closure, tuple(artifacts), tuple(observed_sources), tuple(observed_licenses))
        return closure

    def resolve_selected_backend(
        self, receipt_handle: str, preparation_input_selection_handle: str,
    ) -> RootApplicationBuildBackendClosureReceipt:
        entry = self._entries.get(receipt_handle)
        if (entry is None or entry.receipt._seal is not _BACKEND_RECEIPT_SEAL
                or entry.receipt.expires_monotonic <= self.monotonic()
                or entry.receipt.source_preparation_selection_handle
                   != entry.input_selection.source_preparation_selection_handle):
            raise ApplicationRuntimePreparationDenied("backend closure receipt is absent, stale or detached")
        inputs, source, lock, backend, _consent = self._current_inputs(
            preparation_input_selection_handle)
        receipt = entry.receipt
        if (inputs != entry.input_selection
                or inputs.application_id != receipt.application_id
                or source.receipt_handle != receipt.pyproject_receipt_handle
                or lock.lock_sha256 != inputs.lock_sha256
                or backend.backend != receipt.build_backend
                or hashlib.sha256(_canonical({
                    "application_id": inputs.application_id,
                    "backend": backend.backend,
                    "requirements": backend.requirements,
                })).hexdigest() != receipt.backend_requirement_sha256
                or len(entry.source_observations) != len(_BACKEND_PACKAGES[inputs.application_id])
                or len(entry.license_observations) != len(entry.source_observations)):
            raise ApplicationRuntimePreparationDenied("backend closure no longer matches current source or lock")
        for observation in entry.source_observations:
            if not self.backend_source_observer.verify_current(
                    observation, preparation_input_selection_handle):
                raise ApplicationRuntimePreparationDenied("backend source observation is no longer current")
        current_licenses = tuple(
            self.backend_source_observer.observe_embedded_backend_licenses(
                observation, preparation_input_selection_handle)
            for observation in entry.source_observations)
        if current_licenses != entry.license_observations:
            raise ApplicationRuntimePreparationDenied("backend license evidence is no longer current")
        expected_rows = [
            {"artifact_id": row.artifact_id, "package_name": row.package_name,
             "package_version": row.package_version, "sha256": row.sha256,
             "size_bytes": row.size_bytes, "source_url_sha256": row.source_url_sha256,
             "metadata_sha256": row.metadata_sha256,
             "license_observation_handle": row.license_observation_handle,
             "license_evidence_sha256": license.evidence_sha256,
             "license_member_records": [list(item) for item in license.license_member_records],
             "declared_license_expression": license.declared_license_expression,
             "eligibility": license.eligibility}
            for row, license in zip(entry.artifacts, current_licenses)
        ]
        expected_digest = hashlib.sha256(_canonical({
            "application_id": receipt.application_id,
            "build_backend": receipt.build_backend,
            "backend_requirement_sha256": receipt.backend_requirement_sha256,
            "backend_manifest_artifact_id": receipt.backend_manifest_artifact_id,
            "backend_manifest_sha256": receipt.backend_manifest_sha256,
            "pyproject_receipt_handle": receipt.pyproject_receipt_handle,
            "package_rows": expected_rows,
        })).hexdigest()
        if expected_digest != receipt.backend_closure_sha256:
            raise ApplicationRuntimePreparationDenied("backend closure digest no longer matches held package facts")
        return receipt

    def resolve_backend_artifact(
        self, artifact_receipt_handle: str,
        preparation_input_selection_handle: str,
        closure_receipt_handle: str,
    ) -> tuple[RootApplicationBuildBackendArtifactReceipt, int]:
        closure = self.resolve_selected_backend(
            closure_receipt_handle, preparation_input_selection_handle)
        if artifact_receipt_handle not in closure.package_artifact_receipt_handles:
            raise ApplicationRuntimePreparationDenied(
                "backend package artifact is not a member of the current closure")
        entry = self._entries[closure_receipt_handle]
        index = closure.package_artifact_receipt_handles.index(artifact_receipt_handle)
        artifact = entry.artifacts[index]
        observation = entry.source_observations[index]
        try:
            fd = self.backend_source_observer.open_blob(observation)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or info.st_size != artifact.size_bytes
                    or stat.S_IMODE(info.st_mode) & 0o222
                    or getattr(observation, "device", None) != info.st_dev
                    or getattr(observation, "inode", None) != info.st_ino
                    or RootApplicationOfflinePackageClosureRegistry._hash_fd(
                        fd, artifact.size_bytes) != artifact.sha256):
                os.close(fd)
                raise OSError
            return artifact, fd
        except Exception:
            raise ApplicationRuntimePreparationDenied(
                "held backend wheel CAS object failed current nofollow verification") from None

    def resolve_current_backend_closure_for_selection(
        self, preparation_input_selection_handle: str,
    ) -> RootApplicationBuildBackendClosureReceipt:
        inputs, _source, _lock, _backend, _consent = self._current_inputs(
            preparation_input_selection_handle)
        candidates = [entry for entry in self._entries.values()
                      if entry.input_selection == inputs]
        if len(candidates) != 1:
            raise ApplicationRuntimePreparationDenied(
                "current application has no unique retained PEP 517 backend closure")
        return self.resolve_selected_backend(
            candidates[0].receipt.receipt_handle, preparation_input_selection_handle)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate lock key")
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _norm_name(value: Any) -> str:
    if (not isinstance(value, str) or not value or len(value) > 256
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value)):
        raise ValueError
    return re.sub(r"[-_.]+", "-", value).lower()


def _version_key(value: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\d+(?:\.\d+){0,3}", value):
        raise ValueError
    return tuple(int(item) for item in value.split("."))


def _marker_value(node: ast.AST, *, depth: int = 0) -> str:
    if depth > _MAX_MARKER_DEPTH:
        raise ValueError
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in _MARKER_ENV:
        return _MARKER_ENV[node.id]
    raise ValueError


def _marker_compare(left: str, op: ast.cmpop, right: str) -> bool:
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    if isinstance(op, ast.In):
        return left in right
    if isinstance(op, ast.NotIn):
        return left not in right
    if isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
        if left.startswith("3.") and right[:1].isdigit():
            a, b = _version_key(left), _version_key(right)
            a = a + (0,) * (4 - len(a))
            b = b + (0,) * (4 - len(b))
        else:
            a, b = left, right
        if isinstance(op, ast.Lt):
            return a < b
        if isinstance(op, ast.LtE):
            return a <= b
        if isinstance(op, ast.Gt):
            return a > b
        return a >= b
    raise ValueError


def _eval_marker(expression: Any) -> bool:
    if expression is None:
        return True
    if not isinstance(expression, str) or len(expression) > 4096:
        raise ValueError
    root = ast.parse(expression, mode="eval").body

    def visit(node: ast.AST, depth: int = 0) -> bool:
        if depth > _MAX_MARKER_DEPTH:
            raise ValueError
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            values = [visit(item, depth + 1) for item in node.values]
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not visit(node.operand, depth + 1)
        if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators):
            left = _marker_value(node.left, depth=depth + 1)
            for op, right_node in zip(node.ops, node.comparators):
                right = _marker_value(right_node, depth=depth + 1)
                if not _marker_compare(left, op, right):
                    return False
                left = right
            return True
        raise ValueError

    return visit(root)


def _wheel_tag(filename: str) -> tuple[str, str] | None:
    if not filename.endswith(".whl"):
        return None
    parts = filename[:-4].split("-")
    if len(parts) < 5:
        return None
    python_tag, abi_tag, platform_tag = parts[-3:]
    pythons = python_tag.split(".")
    abis = abi_tag.split(".")
    platforms = platform_tag.split(".")
    best: tuple[int, str] | None = None
    for py in pythons:
        for abi in abis:
            for platform in platforms:
                compatible = (
                    (py == "cp314" and abi == "cp314"
                     and _manylinux_aarch64_compatible(platform))
                    or (_stable_abi_python_tag(py) and abi == "abi3"
                        and _manylinux_aarch64_compatible(platform))
                    or (py in {"py3", "py2.py3"} and abi == "none"
                        and platform == "any")
                )
                if compatible:
                    rank = 0 if platform != "any" else 1
                    tag = f"{py}-{abi}-{platform}"
                    if best is None or rank < best[0]:
                        best = rank, tag
    return None if best is None else (best[1], parts[0])


def _stable_abi_python_tag(tag: str) -> bool:
    match = re.fullmatch(r"cp3([0-9]+)", tag)
    return match is not None and 2 <= int(match.group(1)) <= 14


def _manylinux_aarch64_compatible(platform: str) -> bool:
    if platform == "manylinux2014_aarch64":
        return True
    match = re.fullmatch(r"manylinux_2_([0-9]+)_aarch64", platform)
    return (match is not None and 17 <= int(match.group(1)) <= _TARGET_GLIBC_MINOR)


def _wheel_matches_package(filename: str, package: Mapping[str, Any]) -> bool:
    parts = filename[:-4].split("-") if filename.endswith(".whl") else []
    if len(parts) < 5:
        return False
    try:
        return (_norm_name(parts[0]) == _norm_name(package.get("name"))
                and parts[1] == package.get("version"))
    except ValueError:
        return False


def observe_python_wheel_license(payload: Any, *, expected_artifact_sha256: str,
                                 expected_package_name: str,
                                 expected_package_version: str) -> PythonPackageLicenseEvidence:
    """Observe license evidence from exact, already integrity-verified wheel bytes.

    The result never says a package is approved. License eligibility requires a
    separate source-reviewed policy receipt that covers this exact evidence.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", expected_artifact_sha256):
        raise ApplicationRuntimePreparationDenied("wheel bytes do not match the retained artifact digest")
    if isinstance(payload, bytes):
        payload_size = len(payload)
        stream = io.BytesIO(payload)
        actual_digest = hashlib.sha256(payload).hexdigest()
    else:
        try:
            fd = payload.fileno()
            info = os.fstat(fd)
            payload_size = info.st_size
            digest = hashlib.sha256()
            offset = 0
            while offset < payload_size:
                chunk = os.pread(fd, min(1024 * 1024, payload_size - offset), offset)
                if not chunk:
                    raise ValueError
                digest.update(chunk)
                offset += len(chunk)
            actual_digest = digest.hexdigest()
            stream = payload
            stream.seek(0)
        except (AttributeError, OSError, ValueError):
            raise ApplicationRuntimePreparationDenied("wheel stream is not a stable held file") from None
    if (not 1 <= payload_size <= _MAX_PACKAGE_ARCHIVE_BYTES
            or actual_digest != expected_artifact_sha256):
        raise ApplicationRuntimePreparationDenied("wheel bytes do not match the retained artifact digest")
    try:
        expected_name = _norm_name(expected_package_name)
        with zipfile.ZipFile(stream, mode="r") as archive:
            entries = archive.infolist()
            if not 1 <= len(entries) <= _MAX_ARCHIVE_MEMBERS:
                raise ValueError
            names: set[str] = set()
            expanded = 0
            metadata_entries: list[zipfile.ZipInfo] = []
            for info in entries:
                name = info.filename
                path = PurePosixPath(name)
                mode = (info.external_attr >> 16) & 0xFFFF
                kind = mode & 0o170000
                if (not name or name.startswith("/") or "\\" in name
                        or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
                        or name in names or info.flag_bits & 0x1
                        or info.file_size < 0 or info.compress_size < 0):
                    raise ValueError
                names.add(name)
                expanded += info.file_size
                if expanded > _MAX_ARCHIVE_EXPANDED_BYTES:
                    raise ValueError
                if info.is_dir():
                    if kind not in {0, 0o040000}:
                        raise ValueError
                elif kind not in {0, 0o100000}:
                    raise ValueError
                elif path.name == "METADATA" and path.parent.name.endswith(".dist-info"):
                    metadata_entries.append(info)
            if len(metadata_entries) != 1:
                raise ValueError
            metadata_info = metadata_entries[0]
            if metadata_info.file_size > _MAX_LICENSE_MEMBER_BYTES:
                raise ValueError
            with archive.open(metadata_info, "r") as stream:
                metadata_bytes = stream.read(_MAX_LICENSE_MEMBER_BYTES + 1)
            if len(metadata_bytes) != metadata_info.file_size or len(metadata_bytes) > _MAX_LICENSE_MEMBER_BYTES:
                raise ValueError
            metadata = email.message_from_bytes(metadata_bytes, policy=email.policy.default)
            names_in_metadata = metadata.get_all("Name", [])
            versions_in_metadata = metadata.get_all("Version", [])
            if (len(names_in_metadata) != 1 or len(versions_in_metadata) != 1
                    or _norm_name(names_in_metadata[0]) != expected_name
                    or versions_in_metadata[0] != expected_package_version):
                raise ValueError
            expressions = metadata.get_all("License-Expression", [])
            if len(expressions) > 1 or expressions and not expressions[0].strip():
                raise ValueError
            if expressions:
                declaration = expressions[0].strip()
            else:
                legacy_license = [value.strip() for value in metadata.get_all("License", []) if value.strip()]
                classifiers = [value.strip() for value in metadata.get_all("Classifier", [])
                               if value.startswith("License ::")]
                declaration = "; ".join(legacy_license + classifiers) or None
            license_paths = metadata.get_all("License-File", [])
            normalized_license_paths: list[str] = []
            for item in license_paths:
                item = item.strip()
                path = PurePosixPath(item)
                if (not item or path.is_absolute() or "\\" in item
                        or any(part in {"", ".", ".."} for part in item.split("/"))):
                    raise ValueError
                normalized_license_paths.append(item)
            if len(set(normalized_license_paths)) != len(normalized_license_paths):
                raise ValueError
            dist_info = str(PurePosixPath(metadata_info.filename).parent)
            license_records: list[tuple[str, str, int]] = []
            total_license_bytes = 0
            for relative in sorted(normalized_license_paths):
                member_path = f"{dist_info}/licenses/{relative}"
                matches = [row for row in entries if row.filename == member_path and not row.is_dir()]
                if len(matches) != 1 or matches[0].file_size > _MAX_LICENSE_MEMBER_BYTES:
                    raise ValueError
                info = matches[0]
                with archive.open(info, "r") as stream:
                    body = stream.read(_MAX_LICENSE_MEMBER_BYTES + 1)
                if len(body) != info.file_size or len(body) > _MAX_LICENSE_MEMBER_BYTES:
                    raise ValueError
                total_license_bytes += len(body)
                if total_license_bytes > _MAX_LICENSE_EVIDENCE_BYTES:
                    raise ValueError
                license_records.append((member_path, hashlib.sha256(body).hexdigest(), len(body)))
            if declaration is None and not license_records:
                eligibility = "unavailable"
            else:
                eligibility = "observed-declaration"
            artifact_sha = expected_artifact_sha256
            metadata_sha = hashlib.sha256(metadata_bytes).hexdigest()
            evidence = {
                "artifact_sha256": artifact_sha,
                "package_name": expected_name,
                "package_version": expected_package_version,
                "metadata_kind": "python-core-metadata",
                "metadata_member_path": metadata_info.filename,
                "metadata_member_sha256": metadata_sha,
                "declared_license_expression": declaration,
                "license_member_records": [
                    {"path": path, "sha256": digest, "size_bytes": size}
                    for path, digest, size in license_records
                ],
            }
            evidence_sha256 = hashlib.sha256(
                json.dumps(evidence, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
            ).hexdigest()
            return PythonPackageLicenseEvidence(
                artifact_sha, expected_name, expected_package_version,
                "python-core-metadata", metadata_info.filename, metadata_sha,
                declaration, tuple(license_records), evidence_sha256, eligibility,
            )
    except (OSError, ValueError, zipfile.BadZipFile, email.errors.MessageError, UnicodeError):
        raise ApplicationRuntimePreparationDenied("wheel license metadata is malformed or incomplete") from None


def _wheel_row(package: Mapping[str, Any]) -> LockedPythonWheel | None:
    candidates: list[tuple[int, LockedPythonWheel]] = []
    for wheel in package.get("wheels", ()):
        if not isinstance(wheel, dict) or set(wheel) - {"url", "hash", "size", "upload-time"}:
            continue
        url, integrity, size = wheel.get("url"), wheel.get("hash"), wheel.get("size")
        if (not isinstance(url, str) or not isinstance(integrity, str)
                or type(size) is not int or size <= 0 or size > 2 * 1024**3):
            continue
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org"
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.port not in (None, 443)):
            continue
        match = re.fullmatch(r"(sha256|sha512):([0-9a-f]+)", integrity)
        if match is None:
            continue
        integrity_algorithm, integrity_digest = match.groups()
        expected_width = 64 if integrity_algorithm == "sha256" else 128
        if len(integrity_digest) != expected_width:
            continue
        filename = PurePosixPath(parsed.path).name
        tag = _wheel_tag(filename)
        if tag is None or not _wheel_matches_package(filename, package):
            continue
        rank = 0 if tag[0].split("-")[0] == "cp314" else 1
        candidates.append((rank, LockedPythonWheel(
            _norm_name(package.get("name")), package.get("version"), url,
            integrity_algorithm, integrity_digest, size, filename, tag[0])))
    if not candidates:
        return None
    candidates.sort(key=lambda row: (row[0], row[1].wheel_filename, row[1].url))
    return candidates[0][1]


def select_locked_python_wheels(lock_bytes: bytes, *, application_id: str) -> LockedPythonWheelSelection:
    """Resolve only default transitive deps and select exact Python 3.14 ARM64 wheels.

    Source builds, malformed markers, ambiguous duplicate package versions,
    custom indexes, non-SHA256 integrity, and missing compatible wheels remain
    explicit blockers. This function issues no artifact or license receipt.
    """
    if (application_id not in _PYTHON_LOCK_APPS or not isinstance(lock_bytes, bytes)
            or not 1 <= len(lock_bytes) <= _MAX_LOCK_BYTES):
        raise ApplicationRuntimePreparationDenied("application lock is outside the fixed Python profile contract")
    digest = hashlib.sha256(lock_bytes).hexdigest()
    try:
        document = tomllib.loads(lock_bytes.decode("utf-8"))
        packages = document.get("package")
        if (type(document.get("version")) is not int or document["version"] != 1
                or not isinstance(packages, list) or not 1 <= len(packages) <= _MAX_LOCK_PACKAGES):
            raise ValueError
        by_name: dict[str, list[Mapping[str, Any]]] = {}
        for package in packages:
            if not isinstance(package, dict) or not isinstance(package.get("version"), str):
                raise ValueError
            name = _norm_name(package.get("name"))
            source = package.get("source")
            if not isinstance(source, dict):
                raise ValueError
            by_name.setdefault(name, []).append(package)
        roots = [row for rows in by_name.values() for row in rows
                 if row.get("source") == {"editable": "."}]
        if len(roots) != 1:
            raise ValueError
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError, TypeError):
        raise ApplicationRuntimePreparationDenied("selected uv lock has an unsupported or malformed schema") from None

    selected: dict[str, Mapping[str, Any]] = {}
    pending = [roots[0]]
    blockers: set[str] = set()
    while pending:
        package = pending.pop()
        name = _norm_name(package.get("name"))
        if name in selected:
            continue
        selected[name] = package
        dependencies = package.get("dependencies", [])
        if not isinstance(dependencies, list):
            blockers.add(f"{name}:malformed-dependencies")
            continue
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                blockers.add(f"{name}:malformed-dependency-row")
                continue
            try:
                if not _eval_marker(dependency.get("marker")):
                    continue
                child_name = _norm_name(dependency.get("name"))
            except (ValueError, SyntaxError):
                blockers.add(f"{name}:unsupported-marker")
                continue
            candidates = by_name.get(child_name, [])
            # Multiple versions need a reviewed marker-to-version selection;
            # never pick an arbitrary lock candidate.
            if len(candidates) != 1:
                blockers.add(f"{child_name}:ambiguous-lock-version" if candidates
                             else f"{child_name}:missing-lock-package")
                continue
            pending.append(candidates[0])

    results: list[LockedPythonWheel] = []
    for name, package in sorted(selected.items()):
        if package is roots[0]:
            continue
        source = package.get("source")
        if source != {"registry": "https://pypi.org/simple"}:
            blockers.add(f"{name}:non-pypi-source")
            continue
        wheel = _wheel_row(package)
        if wheel is None:
            blockers.add(f"{name}:no-compatible-cp314-aarch64-wheel")
            continue
        results.append(wheel)
    return LockedPythonWheelSelection(
        application_id, digest, tuple(sorted(_MARKER_ENV.items())),
        tuple(results), tuple(sorted(blockers)))
