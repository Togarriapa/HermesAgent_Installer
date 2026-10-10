"""Root observations for existing private model deployments.

This module deliberately separates selected configuration from observed runtime
evidence.  A connector route, model alias, or caller supplied path can never
mint a deployment receipt.  The low level listener observer below correlates a
loopback LISTEN socket inode with an enrolled process's open file descriptors
and current PID/cgroup/network-namespace identity.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import time
import base64
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Callable, Mapping

from hermes_installer.managed_process_custodian import RemoteOriginKernelProof


_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SOCKET_LINK = re.compile(r"socket:\[(\d+)\]\Z", re.ASCII)
_TCP_STATE_LISTEN = "0A"
_AUTHORITY_KINDS = {
    "private-endpoint": "PrivateEndpointObservation",
    "private-model-deployment": "PrivateModelDeploymentObservation",
    "existing-model-tree": "ExistingModelArtifactObservation",
}


class PrivateDeploymentDenied(RuntimeError):
    """Root could not establish a current exact endpoint/model deployment."""


@dataclass(frozen=True, slots=True)
class LoopbackListenerObservation:
    """Current kernel-derived owner evidence for one IPv4 loopback listener."""

    profile_id: str
    generation: str
    enrollment_id: str
    uid: int
    pid: int
    pid_starttime_ticks: int
    cgroup_id: str
    network_namespace_inode: int
    address: str
    port: int
    socket_inode: int
    owner_fd: int
    observation_sha256: str
    issued_monotonic: float


def _canonical_claims(value: Any) -> dict[str, Any]:
    """Copy a typed receipt's claims to strict canonical JSON-compatible data."""
    def plain(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {str(key): plain(child) for key, child in item.items()}
        if isinstance(item, (tuple, list)):
            return [plain(child) for child in item]
        return item

    result: dict[str, Any] = {}
    for field in fields(value):
        if field.name in {"signature", "receipt_sha256"}:
            continue
        item = getattr(value, field.name)
        result[field.name] = plain(item)
    try:
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        raise PrivateDeploymentDenied("observation claims are not canonical JSON") from None
    if len(encoded) > 1_000_000:
        raise PrivateDeploymentDenied("observation claims exceed the fixed bound")
    return result


@dataclass(frozen=True, slots=True)
class PrivateEndpointObservation:
    schema: int
    receipt_handle: str
    receipt_sha256: str
    boot_id: str
    endpoint_binding_id: str
    endpoint_selection_sha256: str
    profile_id: str
    namespace_id: str
    principal_id: str
    service_enrollment_id: str
    service_generation: str
    process_profile_id: str
    process_profile_generation: str
    endpoint_target_id: str
    connector_route_ids: tuple[str, ...]
    recipient_id: str
    credential_reference_id: str | None
    server_config_artifact_id: str
    server_config_sha256: str
    runtime_artifact_records: tuple[Mapping[str, Any], ...]
    process_identity_digest: str
    kernel_process_receipt_handle: str
    private_network_receipt_handle: str
    listening_endpoint_observation_handle: str
    ownership_observation_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    signature: bytes = b""

    def claims(self) -> dict[str, Any]:
        return _canonical_claims(self)


@dataclass(frozen=True, slots=True)
class PrivateModelDeploymentObservation:
    schema: int
    receipt_handle: str
    receipt_sha256: str
    boot_id: str
    model_binding_id: str
    model_selection_sha256: str
    endpoint_receipt_handle: str
    profile_id: str
    namespace_id: str
    service_enrollment_id: str
    service_generation: str
    source_model_id: str
    source_revision: str
    license_artifact_id: str
    license_sha256: str
    model_artifact_id: str
    model_artifact_sha256: str
    model_tree_manifest_sha256: str
    model_member_observation_sha256: str
    runtime_artifact_id: str
    runtime_artifact_sha256: str
    load_config_artifact_id: str
    load_config_sha256: str
    served_model_id: str
    capability: str
    dimensions: int | None
    process_identity_digest: str
    kernel_process_receipt_handle: str
    load_observation_handle: str
    capability_probe_receipt_handle: str
    issued_monotonic: float
    expires_monotonic: float
    signature: bytes = b""

    def claims(self) -> dict[str, Any]:
        return _canonical_claims(self)


@dataclass(frozen=True, slots=True)
class ExistingModelArtifactObservation:
    observation_handle: str
    selection_handle: str
    artifact_id: str
    source_model_id: str
    source_revision: str
    source_manifest_artifact_id: str
    source_manifest_sha256: str
    license_artifact_id: str
    license_sha256: str
    tree_manifest_sha256: str
    member_observation_sha256: str
    root_device: int
    root_inode: int
    root_uid: int
    root_gid: int
    root_mode: int
    member_count: int
    total_size_bytes: int
    issued_monotonic: float
    expires_monotonic: float
    boot_id: str
    signature: bytes = b""

    def claims(self) -> dict[str, Any]:
        return _canonical_claims(self)


@dataclass(frozen=True, slots=True)
class ExistingModelTreeFacts:
    """Digest and root identity from an already selected held model directory."""

    tree_manifest_sha256: str
    member_observation_sha256: str
    root_device: int
    root_inode: int
    root_uid: int
    root_gid: int
    root_mode: int
    member_count: int
    total_size_bytes: int
    members: tuple[Mapping[str, Any], ...]
    directories: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class VerifiedExistingModelArtifactObservation:
    """Root-local source proof returned before authority signing.

    ``observation`` is the exact unsigned v127 authority DTO. The retained
    observer identity prevents a caller-created DTO from entering the signer.
    """

    observation: ExistingModelArtifactObservation
    observer_id: str


class RootExistingModelArtifactObserver:
    """Observe an already present model tree through a root-held TTY choice.

    The factory owns selection creation. This class accepts only its opaque
    handle and duplicated held directory FD; it never accepts a path.
    """

    def __init__(self, bindings: Any, root_journal: Any, authority_service: Any,
                 root_existing_model_selection_registry: Any, artifact_observer: Any,
                 *, expected_uid: int = 0, monotonic: Callable[[], float] = time.monotonic,
                 boot_id_reader: Callable[[], str] | None = None):
        if (os.geteuid() != expected_uid or expected_uid != 0
                or root_journal is None or authority_service is None
                or root_existing_model_selection_registry is None
                or artifact_observer is None
                or not callable(getattr(root_existing_model_selection_registry, "resolve_selection", None))
                or not callable(getattr(root_existing_model_selection_registry, "verify_current", None))
                or not callable(getattr(root_existing_model_selection_registry, "open_selected_directory", None))
                or not callable(getattr(artifact_observer, "observe", None))
                or not callable(getattr(artifact_observer, "verify_current", None))):
            raise PrivateDeploymentDenied("root-held existing-model observation inputs are unavailable")
        self.bindings = bindings
        self.root_journal = root_journal
        self.authority_service = authority_service
        self.selection_registry = root_existing_model_selection_registry
        self.artifact_observer = artifact_observer
        self.expected_uid = expected_uid
        self._monotonic = monotonic
        self._boot_id_reader = boot_id_reader or (
            lambda: Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip())
        self._observer_id = secrets.token_urlsafe(32)
        self._observations: dict[str, tuple[VerifiedExistingModelArtifactObservation, Any, ExistingModelTreeFacts]] = {}

    @classmethod
    def from_root_runtime(cls, bindings: Any, root_journal: Any,
                          authority_service: Any,
                          root_existing_model_selection_registry: Any, *,
                          artifact_observer: Any = None, expected_uid: int = 0,
                          **kwargs: Any) -> "RootExistingModelArtifactObserver":
        resolver = getattr(bindings, "resolve_root_journal", None)
        generation_digest = getattr(bindings, "service_generation_digest", None)
        if not callable(resolver) or not isinstance(generation_digest, str):
            raise PrivateDeploymentDenied("active protected root-journal resolver is unavailable")
        try:
            selected_journal = resolver(
                "installer-authority-journal-v1",
                expected_active_generation_digest=generation_digest,
            )
        except Exception:
            raise PrivateDeploymentDenied("active protected authority journal is unavailable") from None
        if type(selected_journal) is not type(root_journal) or selected_journal != root_journal:
            raise PrivateDeploymentDenied("existing model observer received a stale root-journal selection")
        if artifact_observer is None:
            from hermes_installer.authority.source_artifact_receipts import RootCatalogArtifactObserver
            staging = getattr(bindings, "artifact_staging_directory", None)
            enrollment = getattr(bindings, "enrollment_catalog", None)
            if not isinstance(staging, Path) or enrollment is None:
                raise PrivateDeploymentDenied("protected artifact staging selection is unavailable")
            # RootCatalogArtifactObserver only consumes these two immutable
            # root-loader projections; no caller controls this adapter.
            from types import SimpleNamespace
            protected = SimpleNamespace(
                protected_enrollment_digest=enrollment.digest,
                artifact_staging_directory=staging,
            )
            artifact_observer = RootCatalogArtifactObserver.from_root_runtime(
                bindings, protected, expected_uid=expected_uid)
        return cls(bindings, root_journal, authority_service,
                   root_existing_model_selection_registry, artifact_observer,
                   expected_uid=expected_uid, **kwargs)

    def observe_selected_tree(self, selection_handle: str) -> VerifiedExistingModelArtifactObservation:
        if (os.geteuid() != self.expected_uid or self.expected_uid != 0
                or not isinstance(selection_handle, str) or not selection_handle
                or len(selection_handle) > 256):
            raise PrivateDeploymentDenied("existing-model source selection handle is unavailable")
        held = None
        manifest_observation = license_observation = None
        try:
            selection = self.selection_registry.resolve_selection(selection_handle)
            self._validate_selection(selection, selection_handle)
            current = self.selection_registry.verify_current(selection)
            if current is not selection:
                raise PrivateDeploymentDenied("existing-model selection is not the retained current object")
            held = self.selection_registry.open_selected_directory(selection_handle)
            if (type(held).__name__ != "RootHeldExistingModelDirectory"
                    or type(held).__module__ != "hermes_installer.authority.bootstrap_runtime_factory"
                    or getattr(held, "selection", None) is not selection):
                raise PrivateDeploymentDenied("held model directory belongs to another selection")
            directory_fd = getattr(held, "directory_fd", -1)
            root_info = os.fstat(directory_fd)
            if (not stat.S_ISDIR(root_info.st_mode)
                    or (root_info.st_dev, root_info.st_ino) != (held.device, held.inode)
                    or root_info.st_uid != self.expected_uid or root_info.st_gid != 0
                    or stat.S_IMODE(root_info.st_mode) != held.mode
                    or root_info.st_mode & 0o022
                    or (held.uid, held.gid) != (self.expected_uid, 0)):
                raise PrivateDeploymentDenied("held model directory identity or ownership is unsafe")

            manifest_observation = self.artifact_observer.observe(
                selection.source_manifest_artifact_id, selection.source_manifest_sha256)
            if not self.artifact_observer.verify_current(manifest_observation):
                raise PrivateDeploymentDenied("pinned model source manifest is not current")
            manifest_fd = manifest_observation.open_blob()
            try:
                metadata = _read_bounded_fd(manifest_fd, 8 * 1024 * 1024)
            finally:
                os.close(manifest_fd)
            from hermes_installer.models.artifacts import ArtifactManifest
            manifest = ArtifactManifest.from_metadata_bytes(metadata)
            if (manifest.model_id != selection.source_model_id
                    or manifest.revision != selection.source_revision
                    or not manifest.fully_verifiable):
                raise PrivateDeploymentDenied("selected source manifest does not match the model choice")

            license_observation = self.artifact_observer.observe(
                selection.license_artifact_id, selection.license_sha256)
            if not self.artifact_observer.verify_current(license_observation):
                raise PrivateDeploymentDenied("selected model license artifact is not current")
            license_fd = license_observation.open_blob()
            try:
                license_bytes = _read_bounded_fd(license_fd, 256 * 1024)
            finally:
                os.close(license_fd)
            if not license_bytes or b"MIT License" not in license_bytes:
                raise PrivateDeploymentDenied("selected GLM source license bytes are not the pinned MIT license")

            facts = inspect_existing_model_tree(directory_fd, manifest, expected_uid=self.expected_uid)
            if not self.artifact_observer.verify_current(manifest_observation) or not self.artifact_observer.verify_current(license_observation):
                raise PrivateDeploymentDenied("source manifest or license changed during tree observation")
            now = self._monotonic()
            deadline = min(float(selection.expires_monotonic), float(held.expires_monotonic), now + 30.0)
            if deadline <= now:
                raise PrivateDeploymentDenied("selected model tree observation lease expired")
            provisional = ExistingModelArtifactObservation(
                observation_handle="existing-model-observation:" + secrets.token_urlsafe(24),
                selection_handle=selection_handle,
                artifact_id="existing-model:" + facts.tree_manifest_sha256,
                source_model_id=selection.source_model_id,
                source_revision=selection.source_revision,
                source_manifest_artifact_id=selection.source_manifest_artifact_id,
                source_manifest_sha256=selection.source_manifest_sha256,
                license_artifact_id=selection.license_artifact_id,
                license_sha256=selection.license_sha256,
                tree_manifest_sha256=facts.tree_manifest_sha256,
                member_observation_sha256=facts.member_observation_sha256,
                root_device=facts.root_device, root_inode=facts.root_inode,
                root_uid=facts.root_uid, root_gid=facts.root_gid, root_mode=facts.root_mode,
                member_count=facts.member_count, total_size_bytes=facts.total_size_bytes,
                issued_monotonic=now, expires_monotonic=deadline,
                boot_id=self._boot_id_reader(), signature=b"",
            )
            verified = VerifiedExistingModelArtifactObservation(provisional, self._observer_id)
            self._observations[provisional.observation_handle] = (verified, selection, facts)
            return verified
        except PrivateDeploymentDenied:
            raise
        except Exception:
            raise PrivateDeploymentDenied("selected existing model tree could not be verified") from None
        finally:
            if held is not None:
                fd = getattr(held, "directory_fd", -1)
                if type(fd) is int and fd >= 0:
                    os.close(fd)
            for item in (manifest_observation, license_observation):
                close = getattr(item, "close", None)
                if callable(close):
                    close()

    def _validate_selection(self, selection: Any, selection_handle: str) -> None:
        if (type(selection).__name__ != "RootExistingModelArtifactSelection"
                or type(selection).__module__ != "hermes_installer.authority.bootstrap_runtime_factory"
                or getattr(selection, "selection_handle", None) != selection_handle):
            raise PrivateDeploymentDenied("model selection was not issued by the protected root setup factory")
        required = ("choice_observation_id", "principal_id", "profile_id", "namespace_id",
                    "model_store_root_id", "model_store_root_receipt_handle", "relative_subpath",
                    "source_model_id", "source_revision", "source_manifest_artifact_id",
                    "source_manifest_sha256", "license_artifact_id", "license_sha256",
                    "controller_binding_handle", "issued_monotonic", "expires_monotonic")
        if any(not getattr(selection, name, None) for name in required):
            raise PrivateDeploymentDenied("protected model source selection is incomplete")
        if (not _SHA256.fullmatch(selection.source_manifest_sha256)
                or not _SHA256.fullmatch(selection.license_sha256)
                or type(selection.issued_monotonic) not in {float, int}
                or type(selection.expires_monotonic) not in {float, int}
                or not selection.issued_monotonic <= self._monotonic() < selection.expires_monotonic
                or selection.expires_monotonic - selection.issued_monotonic > 600):
            raise PrivateDeploymentDenied("protected model source selection has an invalid lease or digest")

    def verify_current(self, verified: VerifiedExistingModelArtifactObservation) -> bool:
        if (type(verified) is not VerifiedExistingModelArtifactObservation
                or verified.observer_id != self._observer_id):
            raise PrivateDeploymentDenied("existing model observation is not from this root observer")
        observation = verified.observation
        retained = self._observations.get(observation.observation_handle)
        if retained is None or retained[0] != verified:
            raise PrivateDeploymentDenied("existing model observation is no longer retained")
        if (observation.boot_id != self._boot_id_reader()
                or not observation.issued_monotonic <= self._monotonic() < observation.expires_monotonic):
            raise PrivateDeploymentDenied("existing model observation is stale")
        current = self.selection_registry.verify_current(retained[1])
        if current is not retained[1]:
            raise PrivateDeploymentDenied("existing model source selection changed")
        self._verify_source_pins_current(retained[1])
        held = self.selection_registry.open_selected_directory(observation.selection_handle)
        try:
            if (type(held).__name__ != "RootHeldExistingModelDirectory"
                    or type(held).__module__ != "hermes_installer.authority.bootstrap_runtime_factory"
                    or getattr(held, "selection", None) is not retained[1]):
                raise PrivateDeploymentDenied("held model directory changed its root selection")
            facts = retained[2]
            if ((held.device, held.inode, held.uid, held.gid, held.mode)
                    != (observation.root_device, observation.root_inode,
                        observation.root_uid, observation.root_gid, observation.root_mode)
                    or facts.tree_manifest_sha256 != observation.tree_manifest_sha256
                    or facts.member_observation_sha256 != observation.member_observation_sha256):
                raise PrivateDeploymentDenied("existing model tree changed since observation")
            _revalidate_existing_model_tree_metadata(held.directory_fd, facts,
                                                    expected_uid=self.expected_uid)
            return True
        finally:
            os.close(held.directory_fd)

    def verify_observation_for_authority(self, observation: ExistingModelArtifactObservation) -> bool:
        pair = self._observations.get(observation.observation_handle)
        return bool(pair and pair[0].observation is observation and self.verify_current(pair[0]))

    def open_member(self, observation_handle: str, relative_manifest_member: str) -> int:
        pair = self._observations.get(observation_handle)
        if pair is None or not self.verify_current(pair[0]):
            raise PrivateDeploymentDenied("existing model member request has no current observation")
        manifest = self._manifest_for_selection(pair[1])
        if relative_manifest_member not in {item.name for item in manifest.files}:
            raise PrivateDeploymentDenied("requested file is not in the exact pinned source manifest")
        held = self.selection_registry.open_selected_directory(pair[0].observation.selection_handle)
        try:
            if (type(held).__name__ != "RootHeldExistingModelDirectory"
                    or type(held).__module__ != "hermes_installer.authority.bootstrap_runtime_factory"
                    or getattr(held, "selection", None) is not pair[1]):
                raise PrivateDeploymentDenied("held model directory changed its root selection")
            current = self.selection_registry.verify_current(pair[1])
            if current is not pair[1]:
                raise PrivateDeploymentDenied("existing model selection changed before member open")
            fd = _open_existing_model_member(held.directory_fd, relative_manifest_member, manifest)
            facts = pair[2]
            row = next((row for row in facts.members if row["path"] == relative_manifest_member), None)
            opened = os.fstat(fd)
            if (row is None or (opened.st_dev, opened.st_ino, opened.st_size,
                    opened.st_mtime_ns, opened.st_ctime_ns) != (row["device"], row["inode"],
                    row["source_size_bytes"], row["mtime_ns"], row["ctime_ns"])):
                os.close(fd)
                raise PrivateDeploymentDenied("selected model member changed after receipt observation")
            return fd
        finally:
            os.close(held.directory_fd)

    def retain_authority_signed_observation(self, receipt: ExistingModelArtifactObservation) -> None:
        pair = self._observations.get(receipt.observation_handle)
        if (pair is None or pair[0].observation.claims() != receipt.claims()
                or not isinstance(receipt.signature, bytes) or len(receipt.signature) != 32
                or not self.verify_current(pair[0])):
            raise PrivateDeploymentDenied("signed model tree receipt does not match a current observation")
        self._observations[receipt.observation_handle] = (
            VerifiedExistingModelArtifactObservation(receipt, self._observer_id), pair[1], pair[2])

    def verify_signed_observation(self, receipt: ExistingModelArtifactObservation) -> bool:
        pair = self._observations.get(receipt.observation_handle)
        if (pair is None or pair[0].observation.claims() != receipt.claims()
                or not receipt.signature or len(receipt.signature) != 32):
            return False
        try:
            return self.verify_current(pair[0])
        except PrivateDeploymentDenied:
            return False

    def _manifest_for_selection(self, selection: Any) -> Any:
        observed = self.artifact_observer.observe(
            selection.source_manifest_artifact_id, selection.source_manifest_sha256)
        try:
            if not self.artifact_observer.verify_current(observed):
                raise PrivateDeploymentDenied("selected source manifest is stale")
            fd = observed.open_blob()
            try:
                from hermes_installer.models.artifacts import ArtifactManifest
                manifest = ArtifactManifest.from_metadata_bytes(_read_bounded_fd(fd, 8 * 1024 * 1024))
            finally:
                os.close(fd)
            if (manifest.model_id != selection.source_model_id
                    or manifest.revision != selection.source_revision
                    or not manifest.fully_verifiable):
                raise PrivateDeploymentDenied("selected model source manifest no longer matches its selection")
            return manifest
        finally:
            observed.close()

    def _verify_source_pins_current(self, selection: Any) -> None:
        observed_manifest = observed_license = None
        try:
            observed_manifest = self.artifact_observer.observe(
                selection.source_manifest_artifact_id, selection.source_manifest_sha256)
            observed_license = self.artifact_observer.observe(
                selection.license_artifact_id, selection.license_sha256)
            if (not self.artifact_observer.verify_current(observed_manifest)
                    or not self.artifact_observer.verify_current(observed_license)):
                raise PrivateDeploymentDenied("selected source metadata or license became stale")
            fd = observed_license.open_blob()
            try:
                if b"MIT License" not in _read_bounded_fd(fd, 256 * 1024):
                    raise PrivateDeploymentDenied("selected GLM source license no longer matches MIT")
            finally:
                os.close(fd)
        finally:
            for item in (observed_manifest, observed_license):
                close = getattr(item, "close", None)
                if callable(close):
                    close()


def _read_bounded_fd(fd: int, maximum: int) -> bytes:
    if type(fd) is not int or fd < 0 or type(maximum) is not int or maximum <= 0:
        raise PrivateDeploymentDenied("protected artifact descriptor or bound is invalid")
    output = bytearray()
    while True:
        block = os.read(fd, min(64 * 1024, maximum + 1 - len(output)))
        if not block:
            break
        output.extend(block)
        if len(output) > maximum:
            raise PrivateDeploymentDenied("protected source metadata exceeds its fixed byte bound")
    return bytes(output)


def _open_existing_model_member(root_fd: int, relative_path: str, manifest: Any) -> int:
    from hermes_installer.models.artifacts import ArtifactManifest
    if (type(manifest) is not ArtifactManifest or not isinstance(relative_path, str)
            or not relative_path or relative_path.startswith("/") or "\\" in relative_path):
        raise PrivateDeploymentDenied("model member path is invalid")
    parts = relative_path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise PrivateDeploymentDenied("model member path escapes the selected tree")
    rows = [item for item in manifest.files if item.name == relative_path]
    if len(rows) != 1 or not rows[0].digest or rows[0].digest_algorithm not in {"sha256", "git-sha1"}:
        raise PrivateDeploymentDenied("model member is not exactly source-pinned")
    parent_fd = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child
        result = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        info = os.fstat(result)
        item = rows[0]
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or info.st_size != item.size):
            os.close(result)
            raise PrivateDeploymentDenied("selected model member identity or size changed")
        source_hash = hashlib.sha256() if item.digest_algorithm == "sha256" else hashlib.sha1()
        if item.digest_algorithm == "git-sha1":
            source_hash.update(f"blob {item.size}\0".encode("ascii"))
        total = 0
        while True:
            block = os.read(result, 1024 * 1024)
            if not block:
                break
            total += len(block)
            source_hash.update(block)
        after = os.fstat(result)
        if (total != item.size or source_hash.hexdigest() != item.digest
                or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                   != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)):
            os.close(result)
            raise PrivateDeploymentDenied("selected model member failed current source digest verification")
        os.lseek(result, 0, os.SEEK_SET)
        return result
    except PrivateDeploymentDenied:
        raise
    except OSError:
        raise PrivateDeploymentDenied("selected model member could not be opened safely") from None
    finally:
        os.close(parent_fd)


def inspect_existing_model_tree(root_fd: int, manifest: Any, *,
                                expected_uid: int = 0) -> ExistingModelTreeFacts:
    """Verify a selected model tree by descriptor without accepting a path.

    The expected manifest is the independently source-pinned
    ``models.artifacts.ArtifactManifest``. Every regular file is opened with
    ``O_NOFOLLOW`` beneath the held directory FD, checked for exact size and
    source digest (SHA-256 or Git blob SHA-1), and also assigned an observed
    SHA-256 plus inode/owner/mode facts. Symlinks, special files, extra files,
    untrusted-writable roots/members, and mutable observations are rejected.
    This function can be expensive on a 429 GB model; it performs no download
    or copy and is called only after an explicit protected existing-tree
    selection.
    """
    if os.geteuid() != expected_uid or expected_uid != 0:
        raise PrivateDeploymentDenied("existing model tree observation requires the root authority")
    return _inspect_existing_model_tree_fd(root_fd, manifest, expected_uid=expected_uid)


def _inspect_existing_model_tree_fd(root_fd: int, manifest: Any, *,
                                    expected_uid: int) -> ExistingModelTreeFacts:
    """Descriptor walker shared with clearly classified unprivileged unit fixtures."""
    from hermes_installer.models.artifacts import ArtifactManifest

    if (type(root_fd) is not int or root_fd < 0 or type(expected_uid) is not int
            or expected_uid < 0 or type(manifest) is not ArtifactManifest
            or not manifest.fully_verifiable):
        raise PrivateDeploymentDenied("existing model tree needs root and a fully pinned source manifest")
    root_info = os.fstat(root_fd)
    if (not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != expected_uid or root_info.st_mode & 0o022):
        raise PrivateDeploymentDenied("selected model root is not a protected root-owned directory")
    expected = {item.name: item for item in manifest.files}
    if len(expected) != len(manifest.files):
        raise PrivateDeploymentDenied("pinned model manifest contains duplicate members")
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []

    def walk(directory_fd: int, prefix: str) -> None:
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError:
            raise PrivateDeploymentDenied("selected model tree could not be enumerated") from None
        for name in names:
            if name in {".", ".."} or "/" in name or "\\" in name:
                raise PrivateDeploymentDenied("selected model tree contains an unsafe member name")
            relative = f"{prefix}/{name}" if prefix else name
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                raise PrivateDeploymentDenied("selected model tree member changed during inspection") from None
            if info.st_uid != expected_uid or info.st_mode & 0o022:
                raise PrivateDeploymentDenied("selected model tree member is writable by an untrusted identity")
            if stat.S_ISDIR(info.st_mode):
                if not any(path.startswith(relative + "/") for path in expected):
                    raise PrivateDeploymentDenied("selected model tree contains an unlisted directory")
                directories.append({
                    "path": relative, "device": info.st_dev, "inode": info.st_ino,
                    "uid": info.st_uid, "gid": info.st_gid,
                    "mode": stat.S_IMODE(info.st_mode), "mtime_ns": info.st_mtime_ns,
                    "ctime_ns": info.st_ctime_ns,
                })
                try:
                    child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                       dir_fd=directory_fd)
                except OSError:
                    raise PrivateDeploymentDenied("selected model tree directory is unsafe") from None
                try:
                    after_open = os.fstat(child_fd)
                    if (after_open.st_dev, after_open.st_ino) != (info.st_dev, info.st_ino):
                        raise PrivateDeploymentDenied("selected model tree directory changed during open")
                    walk(child_fd, relative)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(info.st_mode) or relative not in expected:
                raise PrivateDeploymentDenied("selected model tree contains an extra or special file")
            item = expected[relative]
            if info.st_size != item.size:
                raise PrivateDeploymentDenied("selected model member size differs from source manifest")
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
            except OSError:
                raise PrivateDeploymentDenied("selected model member could not be opened safely") from None
            try:
                before = os.fstat(fd)
                if (before.st_dev, before.st_ino, before.st_size) != (info.st_dev, info.st_ino, info.st_size):
                    raise PrivateDeploymentDenied("selected model member changed before hashing")
                source_hash = hashlib.sha256() if item.digest_algorithm == "sha256" else hashlib.sha1()
                observed_hash = hashlib.sha256()
                if item.digest_algorithm == "git-sha1":
                    source_hash.update(f"blob {item.size}\0".encode("ascii"))
                total_read = 0
                while True:
                    try:
                        block = os.read(fd, 1024 * 1024)
                    except InterruptedError:
                        continue
                    if not block:
                        break
                    total_read += len(block)
                    source_hash.update(block)
                    observed_hash.update(block)
                after = os.fstat(fd)
                if (total_read != item.size or source_hash.hexdigest() != item.digest
                        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                           != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                    raise PrivateDeploymentDenied("selected model member bytes changed or fail source digest")
                rows.append({
                    "path": relative, "kind": "file", "source_size_bytes": item.size,
                    "source_digest_algorithm": item.digest_algorithm,
                    "source_digest": item.digest, "observed_sha256": observed_hash.hexdigest(),
                    "device": before.st_dev, "inode": before.st_ino,
                    "uid": before.st_uid, "gid": before.st_gid,
                    "mode": stat.S_IMODE(before.st_mode),
                    "mtime_ns": before.st_mtime_ns, "ctime_ns": before.st_ctime_ns,
                })
                seen.add(relative)
            finally:
                os.close(fd)

    try:
        walk(root_fd, "")
    except PrivateDeploymentDenied:
        raise
    except OSError:
        raise PrivateDeploymentDenied("selected model tree could not be verified") from None
    if seen != set(expected):
        raise PrivateDeploymentDenied("selected model tree is missing pinned source members")
    rows.sort(key=lambda row: row["path"])
    directories.sort(key=lambda row: row["path"])
    content_manifest = [{
        "path": row["path"], "kind": "file", "size_bytes": row["source_size_bytes"],
        "source_digest_algorithm": row["source_digest_algorithm"],
        "source_digest": row["source_digest"], "observed_sha256": row["observed_sha256"],
    } for row in rows]
    tree_raw = json.dumps(content_manifest, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    tree_digest = hashlib.sha256(tree_raw).hexdigest()
    member_raw = json.dumps({
        "root_device": root_info.st_dev, "root_inode": root_info.st_ino,
        "root_uid": root_info.st_uid, "root_gid": root_info.st_gid,
        "root_mode": stat.S_IMODE(root_info.st_mode), "members": rows,
        "directories": directories,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return ExistingModelTreeFacts(
        tree_digest, hashlib.sha256(member_raw).hexdigest(), root_info.st_dev,
        root_info.st_ino, root_info.st_uid, root_info.st_gid,
        stat.S_IMODE(root_info.st_mode), len(rows), sum(item.size for item in manifest.files),
        tuple(rows), tuple(directories),
    )


def _revalidate_existing_model_tree_metadata(root_fd: int, facts: ExistingModelTreeFacts,
                                            *, expected_uid: int) -> None:
    """Check every held member path/inode/time identity without rehashing huge weights."""
    root = os.fstat(root_fd)
    if (not stat.S_ISDIR(root.st_mode) or (root.st_dev, root.st_ino, root.st_uid,
            root.st_gid, stat.S_IMODE(root.st_mode)) != (facts.root_device, facts.root_inode,
            facts.root_uid, facts.root_gid, facts.root_mode)):
        raise PrivateDeploymentDenied("selected model root identity changed")
    files = {row["path"]: row for row in facts.members}
    dirs = {row["path"]: row for row in facts.directories}
    expected: dict[str, set[str]] = {"": set()}
    for path in (*files, *dirs):
        parts = path.split("/")
        for index, part in enumerate(parts):
            parent = "/".join(parts[:index])
            expected.setdefault(parent, set()).add(part)
    observed_files: set[str] = set()
    observed_dirs: set[str] = set()

    def walk(directory_fd: int, prefix: str) -> None:
        try:
            names = set(os.listdir(directory_fd))
        except OSError:
            raise PrivateDeploymentDenied("selected model directory changed during revalidation") from None
        if names != expected.get(prefix, set()):
            raise PrivateDeploymentDenied("selected model tree membership changed")
        for name in sorted(names):
            if name in {".", ".."} or "/" in name or "\\" in name:
                raise PrivateDeploymentDenied("selected model tree contains an unsafe member")
            relative = f"{prefix}/{name}" if prefix else name
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                raise PrivateDeploymentDenied("selected model member disappeared") from None
            if stat.S_ISDIR(info.st_mode):
                row = dirs.get(relative)
                identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                            stat.S_IMODE(info.st_mode), info.st_mtime_ns, info.st_ctime_ns)
                if row is None or identity != (row["device"], row["inode"], row["uid"],
                        row["gid"], row["mode"], row["mtime_ns"], row["ctime_ns"]):
                    raise PrivateDeploymentDenied("selected model directory identity changed")
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        raise PrivateDeploymentDenied("selected model directory changed while opening")
                    observed_dirs.add(relative)
                    walk(child_fd, relative)
                finally:
                    os.close(child_fd)
                continue
            row = files.get(relative)
            identity = (info.st_dev, info.st_ino, info.st_size, info.st_uid, info.st_gid,
                        stat.S_IMODE(info.st_mode), info.st_mtime_ns, info.st_ctime_ns)
            if (row is None or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != expected_uid or info.st_mode & 0o022
                    or identity != (row["device"], row["inode"], row["source_size_bytes"],
                        row["uid"], row["gid"], row["mode"], row["mtime_ns"], row["ctime_ns"])):
                raise PrivateDeploymentDenied("selected model file identity changed")
            member_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
            try:
                opened = os.fstat(member_fd)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise PrivateDeploymentDenied("selected model file changed while opening")
            finally:
                os.close(member_fd)
            observed_files.add(relative)

    walk(root_fd, "")
    if observed_files != set(files) or observed_dirs != set(dirs):
        raise PrivateDeploymentDenied("selected model tree member set changed")


def _read_pid_stat(path: Path) -> tuple[int, int]:
    """Return PID and Linux start ticks without being confused by ')' in comm."""
    raw = path.read_text(encoding="ascii")
    close = raw.rfind(")")
    if close < 0:
        raise PrivateDeploymentDenied("process stat is malformed")
    try:
        pid = int(raw[:raw.find(" ")])
        fields = raw[close + 2 :].split()  # begins with field 3 (state)
        start_ticks = int(fields[19])  # field 22
    except (ValueError, IndexError):
        raise PrivateDeploymentDenied("process stat is malformed") from None
    return pid, start_ticks


def _tcp4_listener_inodes(table: str, port: int) -> set[int]:
    """Parse only exact 127.0.0.1 IPv4 LISTEN sockets on the selected port."""
    found: set[int] = set()
    for line in table.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        local, state = fields[1], fields[3]
        try:
            address_hex, port_hex = local.split(":", 1)
            inode = int(fields[9], 10)
            local_port = int(port_hex, 16)
        except (ValueError, IndexError):
            continue
        # Linux procfs prints IPv4 address words in host byte order.
        if (address_hex.upper() == "0100007F" and local_port == port
                and state.upper() == _TCP_STATE_LISTEN and inode > 0):
            found.add(inode)
    return found


def inspect_loopback_listener(
    proof: RemoteOriginKernelProof,
    *,
    port: int,
    proc_root: Path = Path("/proc"),
    monotonic: Callable[[], float] = time.monotonic,
) -> LoopbackListenerObservation:
    """Observe an exact IPv4 loopback listener owned by the selected process.

    `proof` must be freshly returned by root custody. The caller must obtain a
    second custody proof after this function and require an exact identity
    match before issuing a durable receipt. This function also brackets its
    procfs reads with PID/starttime/cgroup/netns checks to detect reuse/races.
    """
    if (os.geteuid() != 0 or type(proof) is not RemoteOriginKernelProof
            or type(port) is not int or not 1 <= port <= 65535
            or not proc_root.is_absolute() or time.monotonic() >= proof.expires_monotonic):
        raise PrivateDeploymentDenied("listener observation requires root and a selected process proof")
    root = proc_root / str(proof.pid)
    try:
        before = _read_pid_stat(root / "stat")
        uid_line = next(line for line in (root / "status").read_text(encoding="ascii").splitlines()
                        if line.startswith("Uid:"))
        uid = int(uid_line.split()[1])
        netns = os.stat(root / "ns/net").st_ino
        cgroups = (root / "cgroup").read_text(encoding="ascii")
        tcp = (root / "net/tcp").read_text(encoding="ascii")
        listeners = _tcp4_listener_inodes(tcp, port)
        owned: list[tuple[int, int]] = []
        for fd_path in (root / "fd").iterdir():
            try:
                match = _SOCKET_LINK.fullmatch(os.readlink(fd_path))
                if match and int(match.group(1)) in listeners:
                    owned.append((int(match.group(1)), int(fd_path.name)))
            except (FileNotFoundError, PermissionError, OSError, ValueError):
                continue
        after = _read_pid_stat(root / "stat")
    except (OSError, StopIteration, ValueError):
        raise PrivateDeploymentDenied("selected process listener state is unavailable") from None
    if (before != after or before != (proof.pid, proof.pid_starttime_ticks)
            or uid != proof.uid or netns != proof.network_namespace_inode
            or proof.cgroup_id not in cgroups.splitlines()
            or not owned):
        raise PrivateDeploymentDenied("listener owner does not match the current enrolled process")
    # Capture all observed fields in one canonical digest; no address supplied
    # by a caller is accepted, and wildcard/remote bindings never match.
    record = {
        "profile_id": proof.profile_id,
        "generation": proof.profile_generation,
        "enrollment_id": proof.enrollment_id,
        "uid": proof.uid,
        "pid": proof.pid,
        "pid_starttime_ticks": proof.pid_starttime_ticks,
        "cgroup_id": proof.cgroup_id,
        "network_namespace_inode": proof.network_namespace_inode,
        "address": "127.0.0.1",
        "port": port,
        "socket_inode": min(owned)[0],
        "owner_fds": sorted(fd for _inode, fd in owned),
    }
    digest = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode("utf-8")).hexdigest()
    return LoopbackListenerObservation(
        proof.profile_id, proof.profile_generation, proof.enrollment_id, proof.uid,
        proof.pid, proof.pid_starttime_ticks, proof.cgroup_id,
        proof.network_namespace_inode, "127.0.0.1", port, min(owned)[0], min(fd for _inode, fd in owned),
        digest, monotonic(),
    )


def inspect_enrolled_loopback_listener(custody: Any, profile_id: str,
                                       generation: str, *, port: int = 8000,
                                       proc_root: Path = Path("/proc"),
                                       monotonic: Callable[[], float] = time.monotonic
                                       ) -> tuple[RemoteOriginKernelProof, LoopbackListenerObservation]:
    """Bracket the kernel listener probe with fresh root custody inspections."""
    inspect = getattr(custody, "inspect_enrolled_process", None)
    if not callable(inspect):
        raise PrivateDeploymentDenied("root process custody inspector is unavailable")
    try:
        before = inspect(profile_id, generation)
        if type(before) is not RemoteOriginKernelProof:
            raise PrivateDeploymentDenied("selected service has no current process proof")
        observation = inspect_loopback_listener(before, port=port, proc_root=proc_root,
                                                monotonic=monotonic)
        after = inspect(profile_id, generation)
    except PrivateDeploymentDenied:
        raise
    except Exception:
        raise PrivateDeploymentDenied("selected service listener could not be revalidated") from None
    identity = lambda proof: (
        proof.process_id, proof.enrollment_id, proof.profile_id,
        proof.profile_generation, proof.uid, proof.gid, proof.pid,
        proof.pid_starttime_ticks, proof.executable_device, proof.executable_inode,
        proof.executable_sha256, proof.cgroup_id, proof.mount_namespace_inode,
        proof.network_namespace_inode, proof.pidfd_registry_handle,
    )
    if (type(after) is not RemoteOriginKernelProof or identity(before) != identity(after)
            or monotonic() >= min(before.expires_monotonic, after.expires_monotonic)):
        raise PrivateDeploymentDenied("selected process changed during listener ownership observation")
    return after, observation


class RootPrivateMemoryDeploymentRegistry:
    """Receipt registry factory seam defined by SK-T125/SK-T127.

    Construction intentionally requires the real authority signer, root
    journal, protected selection registry, and current observers. No local
    key, mutable profile dictionary, callback boolean, or network alias can
    substitute for those services.
    """

    def __init__(self, bindings: Any, verified_protected_enrollment: Any,
                 artifact_observer: Any, managed_process_custody: Any,
                 selected_endpoint_connector: Any, root_journal: Any, *,
                 authority_service: Any, existing_model_artifact_observer: Any = None,
                 endpoint_selections: Any, model_selections: Any,
                 boot_id_reader: Callable[[], str] | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
        if (os.geteuid() != 0 or authority_service is None or root_journal is None
                or endpoint_selections is None or model_selections is None
                or not callable(getattr(authority_service, "issue_private_memory_observation", None))
                or not callable(getattr(authority_service, "verify_private_memory_observation", None))
                or not callable(getattr(authority_service, "attach_private_memory_observation_producer", None))
                or not callable(getattr(managed_process_custody, "inspect_enrolled_process", None))
                or not callable(getattr(artifact_observer, "observe", None))
                or not callable(getattr(artifact_observer, "verify_current", None))):
            raise PrivateDeploymentDenied("root private deployment observers are not composed")
        self.bindings = bindings
        self.protected_enrollment = verified_protected_enrollment
        self.artifact_observer = artifact_observer
        self.process_custody = managed_process_custody
        self.connector = selected_endpoint_connector
        self.root_journal = root_journal
        self.authority_service = authority_service
        self.existing_model_artifact_observer = existing_model_artifact_observer
        self.endpoint_selections = endpoint_selections
        self.model_selections = model_selections
        self._boot_id_reader = boot_id_reader or (lambda: Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        self._monotonic = monotonic
        self._pending: dict[int, tuple[str, Any]] = {}
        self._receipts: dict[str, tuple[str, Any]] = {}
        self._journal_dirfds: dict[str, int] = {}
        authority_service.attach_private_memory_observation_producer(self)

    @classmethod
    def from_root_runtime(cls, bindings: Any, verified_protected_enrollment: Any,
                          artifact_observer: Any, managed_process_custody: Any,
                          selected_endpoint_connector: Any, root_journal: Any, *,
                          authority_service: Any, existing_model_artifact_observer: Any = None,
                          endpoint_selections: Any = None, model_selections: Any = None,
                          **kwargs: Any) -> "RootPrivateMemoryDeploymentRegistry":
        """Construct from explicit protected selections; absent projections deny."""
        runtime_catalog = getattr(bindings, "enrollment_catalog", None)
        if (runtime_catalog is None or getattr(verified_protected_enrollment,
                                               "protected_enrollment_digest", None)
                != getattr(runtime_catalog, "digest", None)):
            raise PrivateDeploymentDenied("selected runtime and protected enrollment do not match")
        if endpoint_selections is None:
            endpoint_selections = getattr(bindings, "private_memory_endpoint_selections", None)
        if model_selections is None:
            model_selections = getattr(bindings, "private_memory_model_selections", None)
        if endpoint_selections is None or model_selections is None:
            raise PrivateDeploymentDenied("typed private endpoint/model selections are not enrolled")
        return cls(bindings, verified_protected_enrollment, artifact_observer,
                   managed_process_custody, selected_endpoint_connector, root_journal,
                   authority_service=authority_service,
                   existing_model_artifact_observer=existing_model_artifact_observer,
                   endpoint_selections=endpoint_selections, model_selections=model_selections,
                   **kwargs)

    def observe_selected_endpoint(self, selected_service_binding: Any) -> str:
        raise PrivateDeploymentDenied("protected endpoint selection and connector receipt producer are not yet composed")

    def observe_selected_model_deployment(self, endpoint_receipt_handle: str,
                                          selected_model_binding: Any) -> str:
        raise PrivateDeploymentDenied("protected model selection and actual load observer are not yet composed")

    def resolve_selected_private_route(self, **_kwargs: Any) -> Any:
        raise PrivateDeploymentDenied("no signed current private endpoint deployment receipt is enrolled")

    def revalidate_private_route(self, route: Any, **_kwargs: Any) -> Any:
        raise PrivateDeploymentDenied("private endpoint route receipt is unavailable")

    def resolve_deployment(self, receipt_handle: str, **_kwargs: Any) -> Any:
        raise PrivateDeploymentDenied("no signed current model deployment receipt is enrolled")

    def revalidate_deployment(self, deployment: Any, **_kwargs: Any) -> Any:
        raise PrivateDeploymentDenied("private model deployment receipt is unavailable")

    def observe_existing_model_tree(self, selection_handle: str) -> ExistingModelArtifactObservation:
        """Observe selected bytes, obtain the finite authority signature, and retain it."""
        observer = self.existing_model_artifact_observer
        if observer is None or not callable(getattr(observer, "observe_selected_tree", None)):
            raise PrivateDeploymentDenied("no root-held existing model store selection is enrolled")
        verified = observer.observe_selected_tree(selection_handle)
        if type(verified) is not VerifiedExistingModelArtifactObservation:
            raise PrivateDeploymentDenied("existing model observer returned an untyped source proof")
        candidate = verified.observation
        if not observer.verify_observation_for_authority(candidate):
            raise PrivateDeploymentDenied("existing model source proof is not retained and current")
        self._stage_authority_observation("existing-model-tree", candidate)
        signed = self.authority_service.issue_private_memory_observation(
            "existing-model-tree", candidate)
        self.retain_authority_signed_observation("existing-model-tree", signed)
        return signed

    def resolve_existing_model_tree(self, observation_handle: str) -> ExistingModelArtifactObservation:
        pair = self._receipts.get(observation_handle)
        if pair is None or pair[0] != "existing-model-tree":
            raise PrivateDeploymentDenied("existing model tree receipt is not retained")
        receipt = pair[1]
        if (not self.authority_service.verify_private_memory_observation(receipt)
                or not self.verify_observation_receipt(receipt)):
            raise PrivateDeploymentDenied("existing model tree receipt is stale or invalid")
        return receipt

    def open_existing_model_member(self, observation_handle: str,
                                   relative_manifest_member: str) -> int:
        receipt = self.resolve_existing_model_tree(observation_handle)
        observer = self.existing_model_artifact_observer
        if receipt.observation_handle != observation_handle or observer is None:
            raise PrivateDeploymentDenied("existing model member receipt is unavailable")
        return observer.open_member(observation_handle, relative_manifest_member)

    def _stage_authority_observation(self, observation_kind: str, observation: Any) -> None:
        """Retain one internally produced typed observation for AuthorityService."""
        expected = _observation_type(observation_kind)
        if type(observation) is not expected:
            raise PrivateDeploymentDenied("authority observation kind and exact DTO type differ")
        if getattr(observation, "boot_id", None) != self._boot_id_reader():
            raise PrivateDeploymentDenied("observation belongs to a different boot")
        now = self._monotonic()
        issued, expiry = observation.issued_monotonic, observation.expires_monotonic
        if (type(issued) not in {int, float} or type(expiry) not in {int, float}
                or not issued <= now < expiry or expiry - issued > 30.0
                or observation.signature):
            raise PrivateDeploymentDenied("observation lease is invalid or already signed")
        claims = observation.claims()
        canonical = json.dumps(claims, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode("utf-8")
        expected_sha = hashlib.sha256(canonical).hexdigest()
        declared_sha = getattr(observation, "receipt_sha256", None)
        if declared_sha is not None and declared_sha != expected_sha:
            raise PrivateDeploymentDenied("observation receipt digest does not match its claims")
        handle = getattr(observation, "receipt_handle", getattr(observation, "observation_handle", None))
        if not isinstance(handle, str) or not handle or any(ord(char) < 33 for char in handle):
            raise PrivateDeploymentDenied("observation handle is malformed")
        self._pending[id(observation)] = (observation_kind, observation)

    def verify_observation_for_authority(self, observation_kind: str, observation: Any) -> bool:
        staged = self._pending.get(id(observation))
        if (type(observation) is not _observation_type(observation_kind) or staged is None
                or staged != (observation_kind, observation)
                or getattr(observation, "boot_id", None) != self._boot_id_reader()):
            return False
        now = self._monotonic()
        if not observation.issued_monotonic <= now < observation.expires_monotonic:
            return False
        if observation_kind == "existing-model-tree":
            observer = self.existing_model_artifact_observer
            return bool(observer and observer.verify_observation_for_authority(observation))
        return True

    def retain_authority_signed_observation(self, observation_kind: str,
                                            signed_receipt: Any) -> None:
        staged = self._pending.get(id(signed_receipt))
        # dataclasses.replace creates a new object; match only the staged
        # unsigned object after checking every signed claim is identical.
        if type(signed_receipt) is not _observation_type(observation_kind):
            raise PrivateDeploymentDenied("authority returned the wrong signed observation type")
        unsigned_pair = next((row for row in self._pending.values()
                              if row[0] == observation_kind
                              and row[1].claims() == signed_receipt.claims()), None)
        if unsigned_pair is None or not signed_receipt.signature:
            raise PrivateDeploymentDenied("signed receipt has no exact staged observation")
        if not isinstance(signed_receipt.signature, bytes) or len(signed_receipt.signature) != 32:
            raise PrivateDeploymentDenied("authority returned a malformed observation signature")
        handle = getattr(signed_receipt, "receipt_handle", getattr(signed_receipt, "observation_handle", None))
        if handle in self._receipts:
            raise PrivateDeploymentDenied("receipt is duplicated")
        if observation_kind == "existing-model-tree":
            observer = self.existing_model_artifact_observer
            if observer is None:
                raise PrivateDeploymentDenied("existing model observation producer disappeared")
            observer.retain_authority_signed_observation(signed_receipt)
        if not self._persist_receipt(observation_kind, signed_receipt):
            raise PrivateDeploymentDenied("receipt could not be durably retained")
        self._receipts[handle] = (observation_kind, signed_receipt)
        self._pending.pop(id(unsigned_pair[1]), None)

    def verify_observation_receipt(self, receipt: Any) -> bool:
        if type(receipt) not in {PrivateEndpointObservation,
                                PrivateModelDeploymentObservation,
                                ExistingModelArtifactObservation}:
            return False
        kind = next((name for name, typ in _AUTHORITY_KINDS.items()
                     if type(receipt).__name__ == typ), None)
        handle = getattr(receipt, "receipt_handle", getattr(receipt, "observation_handle", None))
        retained = self._receipts.get(handle)
        retained_receipt = retained[1] if retained else None
        if (kind is None or retained is None or retained[0] != kind or retained_receipt is None
                or retained_receipt.claims() != receipt.claims()
                or retained_receipt.signature != receipt.signature
                or getattr(receipt, "boot_id", None) != self._boot_id_reader()
                or not isinstance(receipt.signature, bytes) or len(receipt.signature) != 32):
            return False
        now = self._monotonic()
        if not receipt.issued_monotonic <= now < receipt.expires_monotonic:
            return False
        if kind == "existing-model-tree":
            observer = self.existing_model_artifact_observer
            return bool(observer and observer.verify_signed_observation(receipt))
        return True

    def _persist_receipt(self, kind: str, receipt: Any) -> bool:
        try:
            child_name = ("existing-model-observations" if kind == "existing-model-tree"
                          else "private-memory-deployments")
            if child_name not in self._journal_dirfds:
                self._journal_dirfds[child_name] = _open_private_child(
                    self.root_journal, child_name,
                )
            journal_dirfd = self._journal_dirfds[child_name]
            value = receipt.claims()
            value["signature"] = base64.b64encode(receipt.signature).decode("ascii")
            value["observation_kind"] = kind
            if hasattr(receipt, "receipt_sha256"):
                value["receipt_sha256"] = receipt.receipt_sha256
            raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
            handle = getattr(receipt, "receipt_handle", getattr(receipt, "observation_handle", ""))
            name = hashlib.sha256((kind + "\0" + str(handle)).encode()).hexdigest() + ".json"
            temp = "." + secrets.token_hex(16) + ".tmp"
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=journal_dirfd)
            try:
                view = memoryview(raw)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError("short receipt write")
                    view = view[count:]
                os.fsync(fd)
                os.fchmod(fd, 0o400)
            finally:
                os.close(fd)
            os.link(temp, name, src_dir_fd=journal_dirfd,
                    dst_dir_fd=journal_dirfd, follow_symlinks=False)
            os.unlink(temp, dir_fd=journal_dirfd)
            os.fsync(journal_dirfd)
            return True
        except (OSError, TypeError, ValueError):
            try:
                os.unlink(temp, dir_fd=journal_dirfd)
            except (OSError, UnboundLocalError):
                pass
            return False


def _observation_type(kind: str) -> type:
    types = {
        "private-endpoint": PrivateEndpointObservation,
        "private-model-deployment": PrivateModelDeploymentObservation,
        "existing-model-tree": ExistingModelArtifactObservation,
    }
    try:
        return types[kind]
    except (KeyError, TypeError):
        raise PrivateDeploymentDenied("private memory observation kind is not allowed") from None


def _open_private_child(root_journal: Any, name: str) -> int:
    """Open/create one fixed 0700 child beneath the held protected journal."""
    from hermes_installer.protected_enrollment import RootJournalSelection

    if (name not in {"private-memory-deployments", "existing-model-observations"}
            or type(root_journal) is not RootJournalSelection or root_journal.root_id != "installer-authority-journal-v1"
            or os.geteuid() != 0):
        raise PrivateDeploymentDenied("protected authority journal selection is unavailable")
    root_fd = os.open(root_journal.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root_info = os.fstat(root_fd)
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or root_info.st_gid != 0
                or stat.S_IMODE(root_info.st_mode) != 0o700
                or (root_info.st_dev, root_info.st_ino) != (root_journal.device, root_journal.inode)):
            raise PrivateDeploymentDenied("protected journal identity changed")
        try:
            os.mkdir(name, 0o700, dir_fd=root_fd)
            os.fsync(root_fd)
        except FileExistsError:
            pass
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=root_fd)
        child_info = os.fstat(child_fd)
        if (not stat.S_ISDIR(child_info.st_mode) or child_info.st_uid != 0
                or child_info.st_gid != 0 or stat.S_IMODE(child_info.st_mode) != 0o700):
            os.close(child_fd)
            raise PrivateDeploymentDenied("private receipt child directory is unsafe")
        return child_fd
    finally:
        os.close(root_fd)


__all__ = [
    "ExistingModelArtifactObservation", "ExistingModelTreeFacts",
    "RootExistingModelArtifactObserver", "VerifiedExistingModelArtifactObservation",
    "LoopbackListenerObservation",
    "PrivateDeploymentDenied", "PrivateEndpointObservation",
    "PrivateModelDeploymentObservation",
    "RootPrivateMemoryDeploymentRegistry", "inspect_enrolled_loopback_listener",
    "inspect_existing_model_tree", "inspect_loopback_listener",
]
