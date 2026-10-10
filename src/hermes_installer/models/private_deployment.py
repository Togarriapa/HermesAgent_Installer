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
    tree_raw = json.dumps(rows, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    tree_digest = hashlib.sha256(tree_raw).hexdigest()
    member_raw = json.dumps({
        "root_device": root_info.st_dev, "root_inode": root_info.st_ino,
        "root_uid": root_info.st_uid, "root_gid": root_info.st_gid,
        "root_mode": stat.S_IMODE(root_info.st_mode), "members": rows,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return ExistingModelTreeFacts(
        tree_digest, hashlib.sha256(member_raw).hexdigest(), root_info.st_dev,
        root_info.st_ino, root_info.st_uid, root_info.st_gid,
        stat.S_IMODE(root_info.st_mode), len(rows), sum(item.size for item in manifest.files),
        tuple(rows),
    )


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
        return observation.issued_monotonic <= now < observation.expires_monotonic

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
        key = (observation_kind, handle)
        if handle in self._receipts or not self._persist_receipt(observation_kind, signed_receipt):
            raise PrivateDeploymentDenied("receipt is duplicated or could not be durably retained")
        self._receipts[handle] = key
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
        if (kind is None or retained != (kind, handle)
                or getattr(receipt, "boot_id", None) != self._boot_id_reader()
                or not isinstance(receipt.signature, bytes) or len(receipt.signature) != 32):
            return False
        now = self._monotonic()
        return receipt.issued_monotonic <= now < receipt.expires_monotonic

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
    "ExistingModelArtifactObservation", "ExistingModelTreeFacts", "LoopbackListenerObservation",
    "PrivateDeploymentDenied", "PrivateEndpointObservation",
    "PrivateModelDeploymentObservation",
    "RootPrivateMemoryDeploymentRegistry", "inspect_enrolled_loopback_listener",
    "inspect_existing_model_tree", "inspect_loopback_listener",
]
