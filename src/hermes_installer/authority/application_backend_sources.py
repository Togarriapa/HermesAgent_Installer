"""Finite source receipts for the selected application's PEP 517 wheels.

This is deliberately separate from both the runtime-lock package source
observer and the Node/Bun toolchain source observer.  The only URLs accepted
come from the held v152 policy member and every retained byte is reopened from
the private root CAS before use.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from hermes_installer.protected_enrollment import RootJournalSelection
from .application_runtime_preparation import (
    ApplicationRuntimePreparationDenied,
    _BACKEND_PACKAGES,
    _BACKEND_POLICY_ARTIFACT_ID,
    _BACKEND_POLICY_SHA256,
    _canonical,
    _valid_opaque,
    inspect_reviewed_backend_wheel,
)

_POLICY_PATH = "plans/amendments/2026-10-10-pep517-backend-source-closure-v152/application-pep517-backend-source-table-v1.json"
_POLICY_BYTES = 15_907
_MAX_WHEEL_BYTES = 1_048_576
_MAX_TTL = 1800.0
_PHASE_ID = "acquire-locked-runtime-packages"
_RECEIPT_SEAL = object()


class BackendSourceDenied(PermissionError):
    """The selected backend source or package bytes are not currently trusted."""


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedApplicationBackendSourceObservation:
    schema: int
    source_observation_handle: str
    policy_artifact_id: str
    policy_sha256: str
    policy_member_receipt_handle: str
    preparation_input_selection_handle: str
    source_preparation_receipt_handle: str
    pyproject_receipt_handle: str
    qualification_choice_handle: str
    package_name: str
    package_version: str
    filename: str
    source_url_sha256: str
    sha256: str
    size_bytes: int
    device: int
    inode: int
    mode: int
    metadata_sha256: str
    license_observation_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _RECEIPT_SEAL:
            raise TypeError("backend source observations are minted by the root observer")


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationBackendLicenseObservation:
    schema: int
    license_observation_handle: str
    source_observation_handle: str
    policy_artifact_id: str
    policy_sha256: str
    package_name: str
    package_version: str
    artifact_sha256: str
    metadata_member_path: str
    metadata_member_sha256: str
    declared_license_expression: str | None
    license_member_records: tuple[tuple[str, str, int], ...]
    evidence_sha256: str
    eligibility: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _RECEIPT_SEAL:
            raise TypeError("backend license observations are minted by the root observer")


@dataclass(slots=True)
class _SourceEntry:
    observation: VerifiedApplicationBackendSourceObservation
    license_observation: RootApplicationBackendLicenseObservation | None
    fd: int
    selection: Any
    source: Any
    lock: Any
    policy_receipt_handle: str


class RootSelectedApplicationBackendSourceObserver:
    """Acquire only the exact v152 wheel closure for a current early selection."""

    def __init__(self, *, selected_installation_binding: Any,
                 verified_installer_release: Any, source_preparation_registry: Any,
                 setup_choice_registry: Any, root_journal: RootJournalSelection,
                 expected_uid: int = 0, monotonic=time.monotonic,
                 ttl_seconds: float = 900.0, download_timeout: float = 30.0) -> None:
        if (expected_uid != 0 or os.geteuid() != 0
                or type(root_journal) is not RootJournalSelection
                or not callable(getattr(verified_installer_release, "verify_current", None))
                or not callable(getattr(verified_installer_release,
                                        "resolve_reviewed_source_artifact", None))
                or not callable(getattr(verified_installer_release,
                                        "open_reviewed_source_artifact", None))
                or not callable(getattr(source_preparation_registry, "resolve_selection", None))
                or not callable(getattr(source_preparation_registry,
                                        "resolve_current_prepared_source_for_selection", None))
                or not callable(getattr(source_preparation_registry,
                                        "resolve_current_lock_for_selection", None))
                or not callable(getattr(source_preparation_registry, "read_current_source_members", None))
                or not callable(getattr(source_preparation_registry, "read_current_lock_bytes", None))
                or not callable(getattr(setup_choice_registry,
                                        "resolve_application_qualification_consent", None))
                or not 0 < ttl_seconds <= _MAX_TTL
                or not 0 < download_timeout <= 60):
            raise ValueError("root backend source observer bindings are unavailable")
        self.binding = selected_installation_binding
        self.release = verified_installer_release
        self.source_registry = source_preparation_registry
        self.choice_registry = setup_choice_registry
        self.root_journal = root_journal
        self.monotonic = monotonic
        self.ttl_seconds = float(ttl_seconds)
        self.download_timeout = float(download_timeout)
        self._sources: dict[str, _SourceEntry] = {}
        self._policies: dict[str, tuple[bytes, Any]] = {}
        self._cas_fd = -1

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        verified_installer_release: Any,
                        source_preparation_registry: Any,
                        setup_choice_registry: Any,
                        root_journal: RootJournalSelection,
                        **kwargs: Any) -> "RootSelectedApplicationBackendSourceObserver":
        return cls(selected_installation_binding=selected_installation_binding,
                   verified_installer_release=verified_installer_release,
                   source_preparation_registry=source_preparation_registry,
                   setup_choice_registry=setup_choice_registry,
                   root_journal=root_journal, **kwargs)

    def close(self) -> None:
        for entry in self._sources.values():
            if entry.fd >= 0:
                os.close(entry.fd)
                entry.fd = -1
        if self._cas_fd >= 0:
            os.close(self._cas_fd)
            self._cas_fd = -1

    def _policy(self) -> tuple[bytes, Any]:
        self.release.verify_current()
        row = self.release.resolve_reviewed_source_artifact(_BACKEND_POLICY_ARTIFACT_ID)
        fd = self.release.open_reviewed_source_artifact(_BACKEND_POLICY_ARTIFACT_ID)
        try:
            info = os.fstat(fd)
            if (row.relative_path != _POLICY_PATH or row.sha256 != _BACKEND_POLICY_SHA256
                    or row.size_bytes != _POLICY_BYTES or info.st_size != _POLICY_BYTES
                    or info.st_uid != 0 or not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1):
                raise BackendSourceDenied("held PEP 517 source table differs from v152")
            payload = _read_fd(fd, _POLICY_BYTES)
            if hashlib.sha256(payload).hexdigest() != _BACKEND_POLICY_SHA256:
                raise BackendSourceDenied("held PEP 517 source table failed its pinned digest")
            value = json.loads(payload, object_pairs_hook=_unique_pairs)
            if (not isinstance(value, dict) or value.get("schema") != 1
                    or value.get("artifact_id") != _BACKEND_POLICY_ARTIFACT_ID
                    or not isinstance(value.get("packages"), list)):
                raise BackendSourceDenied("held PEP 517 source table schema is invalid")
            self._validate_table(value)
            handle = f"release-member-{row.sha256}"
            self._policies[handle] = (payload, row)
            return payload, row
        except BackendSourceDenied:
            raise
        except Exception:
            raise BackendSourceDenied("held PEP 517 source table is malformed") from None
        finally:
            os.close(fd)

    @staticmethod
    def _validate_table(table: Mapping[str, Any]) -> None:
        rows = table["packages"]
        found = {(row.get("name"), row.get("version")) for row in rows if isinstance(row, dict)}
        expected = {(name, version) for group in _BACKEND_PACKAGES.values() for name, version in group}
        if found != expected or len(rows) != len(expected):
            raise BackendSourceDenied("v152 backend table package set differs from fixed app profiles")
        for row in rows:
            if (not isinstance(row, dict) or row.get("integrity_algorithm") != "sha256"
                    or not isinstance(row.get("url"), str)
                    or not row["url"].startswith("https://files.pythonhosted.org/packages/")
                    or row.get("size_bytes", _MAX_WHEEL_BYTES + 1) > _MAX_WHEEL_BYTES
                    or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", "")))
                    or row.get("requires_dist") is not None
                       and not isinstance(row.get("requires_dist"), list)
                    or not isinstance(row.get("license_members"), list)):
                raise BackendSourceDenied("v152 backend table contains an unsupported row")

    def _current(self, input_handle: str) -> tuple[Any, Any, Any, Any, Any, bytes]:
        from .application_runtime_selection import RootApplicationRuntimePreparationInputSelection
        try:
            inputs = self.binding.resolve_application_runtime_preparation_input_selection(input_handle)
            if (type(inputs) is not RootApplicationRuntimePreparationInputSelection
                    or inputs.selection_handle != input_handle or inputs.runtime_kind != "python"
                    or inputs.application_id not in _BACKEND_PACKAGES
                    or inputs.expires_monotonic <= self.monotonic()):
                raise ValueError
            selection = self.source_registry.resolve_selection(
                inputs.source_preparation_selection_handle)
            source = self.source_registry.resolve_current_prepared_source_for_selection(
                inputs.source_preparation_selection_handle)
            lock = self.source_registry.resolve_current_lock_for_selection(
                inputs.source_preparation_selection_handle, source.receipt_handle)
            pyproject = self.source_registry.read_current_source_members(
                inputs.source_preparation_selection_handle, source.receipt_handle,
                ("pyproject.toml",))["pyproject.toml"]
            lock_bytes = self.source_registry.read_current_lock_bytes(
                lock.receipt_handle, inputs.source_preparation_selection_handle,
                source.receipt_handle)
            if (selection.selection_handle != inputs.source_preparation_selection_handle
                    or source.receipt_handle != inputs.prepared_source_receipt_handle
                    or lock.receipt_handle != inputs.selected_lock_receipt_handle
                    or lock.lock_sha256 != inputs.lock_sha256
                    or hashlib.sha256(lock_bytes).hexdigest() != inputs.lock_sha256
                    or not isinstance(pyproject, bytes)):
                raise ValueError
            from .application_runtime_preparation import inspect_application_build_backend
            backend = inspect_application_build_backend(inputs.application_id, pyproject)
            consent = self.choice_registry.resolve_application_qualification_consent(
                inputs.qualification_choice_handle, _PHASE_ID)
            controller = self.binding.resolve_application_controller_binding(
                inputs.qualification_choice_handle)
            if (getattr(consent, "qualification_choice_handle", None) != inputs.qualification_choice_handle
                    or getattr(consent, "application_id", None) != inputs.application_id
                    or _PHASE_ID not in getattr(consent, "allowed_phase_ids", ())
                    or getattr(consent, "additional_metered_budget_usd", None) != 0.0
                    or not self.monotonic() < getattr(consent, "expires_monotonic", 0)
                       <= self.monotonic() + 30.0
                    or getattr(controller, "handle", None) != inputs.controller_binding_handle
                    or getattr(controller, "expires_monotonic", 0) <= self.monotonic()
                    or not self.binding.verify_application_controller_binding(controller)):
                raise ValueError
            return inputs, selection, source, lock, backend, pyproject
        except Exception:
            raise BackendSourceDenied("current selected source, lock, backend, consent or controller is unavailable") from None

    def _cas_directory(self) -> int:
        path = self.root_journal.path
        info = path.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (self.root_journal.device, self.root_journal.inode)):
            raise BackendSourceDenied("root backend CAS anchor changed")
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for name in ("application-backend-packages", "sha256"):
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=fd)
                st = os.fstat(nxt)
                if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
                    os.close(nxt)
                    raise BackendSourceDenied("backend CAS directory is not root-private")
                os.close(fd)
                fd = nxt
            return fd
        except Exception:
            os.close(fd)
            raise

    def _check_cas(self) -> int:
        if self._cas_fd < 0:
            self._cas_fd = self._cas_directory()
        st = os.fstat(self._cas_fd)
        try:
            anchor = self.root_journal.path.stat(follow_symlinks=False)
        except OSError:
            anchor = None
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700
                or anchor is None or not stat.S_ISDIR(anchor.st_mode) or anchor.st_uid != 0
                or stat.S_IMODE(anchor.st_mode) != 0o700
                or (anchor.st_dev, anchor.st_ino)
                   != (self.root_journal.device, self.root_journal.inode)):
            raise BackendSourceDenied("backend CAS directory identity changed")
        return self._cas_fd

    def _source_row(self, package_name: str, inputs: Any, backend: Any,
                    policy: Mapping[str, Any]) -> Mapping[str, Any]:
        allowed = _BACKEND_PACKAGES[inputs.application_id]
        versions = dict(allowed)
        if package_name not in versions:
            raise BackendSourceDenied("package is outside selected app's fixed backend closure")
        rows = [row for row in policy["packages"]
                if row.get("name") == package_name and row.get("version") == versions[package_name]]
        if len(rows) != 1:
            raise BackendSourceDenied("selected package has no unique v152 source row")
        # Backend dependencies are derived from the source's actual build-system
        # declaration; profiles cannot silently fetch unrelated table entries.
        if package_name not in {name for name, _version in allowed}:
            raise BackendSourceDenied("package is not required by the selected PEP 517 profile")
        return rows[0]

    def observe_selected_backend_source(self, preparation_input_selection_handle: str,
                                       package_name: str) -> VerifiedApplicationBackendSourceObservation:
        inputs, selection, source, lock, backend, _pyproject = self._current(
            preparation_input_selection_handle)
        policy_bytes, policy_member = self._policy()
        policy = json.loads(policy_bytes)
        row = self._source_row(package_name, inputs, backend, policy)
        # A package can be fetched only under fresh same-choice phase consent.
        consent = self.choice_registry.resolve_application_qualification_consent(
            inputs.qualification_choice_handle, _PHASE_ID)
        controller = self.binding.resolve_application_controller_binding(
            inputs.qualification_choice_handle)
        now = self.monotonic()
        if (getattr(consent, "qualification_choice_handle", None)
                != inputs.qualification_choice_handle
                or getattr(consent, "application_id", None) != inputs.application_id
                or _PHASE_ID not in getattr(consent, "allowed_phase_ids", ())
                or getattr(consent, "additional_metered_budget_usd", None) != 0.0
                or not now < getattr(consent, "expires_monotonic", 0) <= now + 30.0
                or getattr(controller, "handle", None) != inputs.controller_binding_handle
                or getattr(controller, "expires_monotonic", 0) <= now
                or not self.binding.verify_application_controller_binding(controller)):
            raise BackendSourceDenied("fresh zero-budget consent and live controller are required")
        url = row.get("url")
        if (not isinstance(url, str) or urllib_parse(url) is False
                or row.get("size_bytes", 0) <= 0 or row["size_bytes"] > _MAX_WHEEL_BYTES):
            raise BackendSourceDenied("selected backend URL or size is outside fixed policy")
        # No redirects, ambient proxy, credentials, or caller-selected URL.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(url, headers={
            "Accept-Encoding": "identity", "User-Agent": "hermes-installer-backend-receipts/1"})
        cas_fd = self._check_cas()
        digest_expected = row["sha256"]
        temp = f".pending-{secrets.token_hex(20)}"
        temp_fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=cas_fd)
        final_fd = -1
        digest = hashlib.sha256()
        total = 0
        try:
            # Freshness is checked immediately before each exact GET.
            inputs2, selection2, source2, lock2, backend2, _ = self._current(
                preparation_input_selection_handle)
            fresh_consent = self.choice_registry.resolve_application_qualification_consent(
                inputs.qualification_choice_handle, _PHASE_ID)
            fresh_controller = self.binding.resolve_application_controller_binding(
                inputs.qualification_choice_handle)
            now = self.monotonic()
            if (not now < getattr(fresh_consent, "expires_monotonic", 0) <= now + 30.0
                    or getattr(fresh_consent, "qualification_choice_handle", None)
                       != inputs.qualification_choice_handle
                    or getattr(fresh_consent, "application_id", None) != inputs.application_id
                    or _PHASE_ID not in getattr(fresh_consent, "allowed_phase_ids", ())
                    or getattr(fresh_consent, "additional_metered_budget_usd", None) != 0.0
                    or getattr(fresh_controller, "handle", None) != inputs.controller_binding_handle
                    or getattr(fresh_controller, "expires_monotonic", 0) <= now
                    or not self.binding.verify_application_controller_binding(fresh_controller)):
                raise BackendSourceDenied("fresh acquisition permission expired before request")
            self.release.verify_current()
            policy2, policy_member2 = self._policy()
            if (inputs2 != inputs or selection2 != selection or source2.receipt_handle != source.receipt_handle
                    or lock2.lock_sha256 != lock.lock_sha256 or backend2 != backend
                    or policy2 != policy_bytes or policy_member2.sha256 != policy_member.sha256
                    or fresh_consent.expires_monotonic <= self.monotonic()):
                raise BackendSourceDenied("source, lock, policy or consent changed before backend GET")
            with opener.open(request, timeout=self.download_timeout) as response:
                if (response.getcode() != 200 or response.geturl() != url
                        or response.headers.get("Content-Encoding") not in (None, "identity")):
                    raise BackendSourceDenied("backend source response was redirected or transformed")
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdecimal() or int(length) != row["size_bytes"]):
                    raise BackendSourceDenied("backend wheel response size header is inconsistent")
                while True:
                    chunk = response.read(min(64 * 1024, row["size_bytes"] + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > row["size_bytes"] or total > _MAX_WHEEL_BYTES:
                        raise BackendSourceDenied("backend wheel exceeded its pinned byte bound")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        count = os.write(temp_fd, view)
                        view = view[count:]
            if total != row["size_bytes"] or digest.hexdigest() != digest_expected:
                raise BackendSourceDenied("backend wheel differs from held v152 size or SHA-256")
            os.fsync(temp_fd)
            os.fchmod(temp_fd, 0o444)
            os.fsync(temp_fd)
            info = os.fstat(temp_fd)
            if (info.st_uid != 0 or info.st_size != total or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o444):
                raise BackendSourceDenied("staged backend wheel failed private CAS custody")
            os.close(temp_fd)
            temp_fd = -1
            final_name = f"app-backend-wheel-{digest_expected}"
            try:
                os.link(temp, final_name, src_dir_fd=cas_fd, dst_dir_fd=cas_fd, follow_symlinks=False)
            except FileExistsError:
                pass
            os.unlink(temp, dir_fd=cas_fd)
            os.fsync(cas_fd)
            final_fd = os.open(final_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=cas_fd)
            final_info = os.fstat(final_fd)
            if (not stat.S_ISREG(final_info.st_mode) or final_info.st_uid != 0
                    or final_info.st_nlink != 1 or final_info.st_size != total
                    or stat.S_IMODE(final_info.st_mode) != 0o444
                    or _hash_fd(final_fd, total) != digest_expected):
                os.close(final_fd)
                raise BackendSourceDenied("published backend wheel CAS object failed verification")
            os.lseek(final_fd, 0, os.SEEK_SET)
            payload = _read_fd(final_fd, total)
            inspection = inspect_reviewed_backend_wheel(payload, row)
            now = self.monotonic()
            expiry = min(now + self.ttl_seconds, inputs.expires_monotonic,
                         selection.expires_monotonic, source.expires_monotonic,
                         lock.expires_monotonic)
            if expiry <= now:
                os.close(final_fd)
                final_fd = -1
                raise BackendSourceDenied("backend source receipt expired during acquisition")
            handle = secrets.token_urlsafe(36)
            license_handle = secrets.token_urlsafe(36)
            observation = VerifiedApplicationBackendSourceObservation(
                1, handle, _BACKEND_POLICY_ARTIFACT_ID, _BACKEND_POLICY_SHA256,
                f"release-member-{policy_member.sha256}", preparation_input_selection_handle,
                source.receipt_handle, source.receipt_handle, inputs.qualification_choice_handle,
                inspection.package_name, inspection.package_version, inspection.filename,
                hashlib.sha256(url.encode("utf-8")).hexdigest(), inspection.artifact_sha256,
                inspection.size_bytes, final_info.st_dev, final_info.st_ino,
                stat.S_IMODE(final_info.st_mode), inspection.metadata_member_sha256,
                license_handle, now, expiry, _seal=_RECEIPT_SEAL)
            self._sources[handle] = _SourceEntry(
                observation, None, final_fd, selection, source, lock,
                observation.policy_member_receipt_handle)
            final_fd = -1
            return observation
        except Exception:
            if temp_fd >= 0:
                os.close(temp_fd)
            if final_fd >= 0:
                os.close(final_fd)
            try:
                os.unlink(temp, dir_fd=cas_fd)
            except OSError:
                pass
            raise

    def verify_current(self, observation: VerifiedApplicationBackendSourceObservation,
                       preparation_input_selection_handle: str) -> bool:
        if (type(observation) is not VerifiedApplicationBackendSourceObservation
                or observation._seal is not _RECEIPT_SEAL
                or observation.preparation_input_selection_handle != preparation_input_selection_handle
                or observation.expires_monotonic <= self.monotonic()):
            return False
        entry = self._sources.get(observation.source_observation_handle)
        if entry is None or entry.observation is not observation or entry.fd < 0:
            return False
        try:
            inputs, selection, source, lock, backend, pyproject = self._current(
                preparation_input_selection_handle)
            self.release.verify_current()
            _policy, member = self._policy()
            info = os.fstat(entry.fd)
            if (inputs.qualification_choice_handle != observation.qualification_choice_handle
                    or source.receipt_handle != observation.source_preparation_receipt_handle
                    or source.receipt_handle != observation.pyproject_receipt_handle
                    or lock.receipt_handle != entry.lock.receipt_handle
                    or member.sha256 != observation.policy_sha256
                    or info.st_dev != observation.device or info.st_ino != observation.inode
                    or stat.S_IMODE(info.st_mode) != observation.mode or info.st_size != observation.size_bytes
                    or _hash_fd(entry.fd, info.st_size) != observation.sha256):
                return False
            return True
        except Exception:
            return False

    def open_blob(self, observation: VerifiedApplicationBackendSourceObservation) -> int:
        if not self.verify_current(observation, observation.preparation_input_selection_handle):
            raise BackendSourceDenied("backend source observation is stale")
        entry = self._sources[observation.source_observation_handle]
        return os.dup(entry.fd)

    def observe_embedded_backend_licenses(
        self, observation: VerifiedApplicationBackendSourceObservation,
        preparation_input_selection_handle: str,
    ) -> RootApplicationBackendLicenseObservation:
        if not self.verify_current(observation, preparation_input_selection_handle):
            raise BackendSourceDenied("backend wheel is not current for selected application")
        entry = self._sources[observation.source_observation_handle]
        if entry.license_observation is not None:
            return entry.license_observation
        from .application_runtime_preparation import observe_python_wheel_license
        with os.fdopen(os.dup(entry.fd), "rb") as stream:
            evidence = observe_python_wheel_license(
                stream, expected_artifact_sha256=observation.sha256,
                expected_package_name=observation.package_name,
                expected_package_version=observation.package_version)
        result = RootApplicationBackendLicenseObservation(
            1, observation.license_observation_handle, observation.source_observation_handle,
            observation.policy_artifact_id, observation.policy_sha256,
            observation.package_name, observation.package_version, observation.sha256,
            evidence.metadata_member_path, evidence.metadata_member_sha256,
            evidence.declared_license_expression, evidence.license_member_records,
            evidence.evidence_sha256, evidence.eligibility, self.monotonic(),
            observation.expires_monotonic, _seal=_RECEIPT_SEAL)
        entry.license_observation = result
        return result


def urllib_parse(url: str) -> bool:
    import urllib.parse
    try:
        parsed = urllib.parse.urlsplit(url)
        return (parsed.scheme == "https" and parsed.hostname == "files.pythonhosted.org"
                and parsed.port in (None, 443) and parsed.username is None and parsed.password is None
                and not parsed.query and not parsed.fragment and parsed.path.startswith("/packages/"))
    except (TypeError, ValueError):
        return False


def _read_fd(fd: int, size: int) -> bytes:
    if type(size) is not int or not 0 <= size <= _MAX_WHEEL_BYTES and size != _POLICY_BYTES:
        raise BackendSourceDenied("read exceeds finite artifact bound")
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(fd, min(64 * 1024, size - offset), offset)
        if not chunk:
            raise BackendSourceDenied("held artifact is truncated")
        chunks.append(chunk)
        offset += len(chunk)
    return b"".join(chunks)


def _hash_fd(fd: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(fd, min(64 * 1024, size - offset), offset)
        if not chunk:
            raise BackendSourceDenied("held CAS object is truncated")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate policy member")
        result[key] = value
    return result
