"""Root-issued active proof for the one fixed Hermes CLI worker launch.

This module only proves the immutable selection and its current held inputs.
It deliberately does not launch the application or turn a module allowlist
into an effect grant; the manager's separate kernel gate must still succeed.
"""
from __future__ import annotations

import hashlib
import importlib
import functools
import json
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .types import AuthorityDenied


def _owner_locked(method):
    @functools.wraps(method)
    def invoke(self, *args, **kwargs):
        lock = getattr(self, "_lock", None)
        if lock is None:
            return method(self, *args, **kwargs)
        with lock:
            return method(self, *args, **kwargs)
    return invoke


class NativeHermesWorkerLaunchUnavailable(AuthorityDenied):
    def __init__(self, message: str):
        super().__init__("native_worker.launch", message)


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeHermesWorkerSelection:
    """Opaque request to resolve one already active network/profile pair."""

    network_id: str
    profile_id: str
    selection_handle: str
    expires_monotonic: float
    _network_projection: Any = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootNativeHermesWorkerSelection(<active selection>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedNativeWorkerViewMount:
    """One exact, root-issued immutable source root in the closed worker view."""

    schema: int
    view_kind: str
    source_root_receipt_handle: str
    source_host_root_path: Path
    source_root_device: int
    source_root_inode: int
    source_closure_sha256: str
    worker_mount_path: str
    read_only: bool
    noexec: bool


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedNativeWorkerView:
    """Private immutable set of selected roots visible to one fixed helper."""

    process_id: str
    worker_executable_path: str
    worker_argv: tuple[str, ...]
    worker_environment: tuple[tuple[str, str], ...]
    selected_view_sha256: str
    mounts: tuple[RootSelectedNativeWorkerViewMount, ...]
    _launch_handle: str = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootObservedNativeWorkerView:
    """Kernel-observed selected mount view for one retained worker PID."""

    schema: int
    observation_handle: str
    launch_handle: str
    process_id: str
    process_pid: int
    process_start_ticks: int
    cgroup_identity: str
    process_uid: int
    process_gid: int
    mount_namespace_inode: int
    network_namespace_inode: int
    selected_view_sha256: str
    observed_monotonic: float
    expires_monotonic: float
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootObservedNativeWorkerView(<kernel-held native view>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootVerifiedNativeHermesWorkerLaunch:
    """Short-lived manager proof binding active source, PM, listener and argv."""

    launch_handle: str
    network_id: str
    profile_id: str
    profile_generation: str
    service_generation_digest: str
    publication_receipt_handle: str
    publication_sha256: str
    active_generation_id: str
    source_choice_signed_record_sha256: str
    runtime_record_id: str
    runtime_record_sha256: str
    pm_runtime_receipt_handle: str
    pm_runtime_closure_sha256: str
    executable_path: Path
    executable_sha256: str
    executable_device: int
    executable_inode: int
    executable_uid: int
    executable_gid: int
    executable_mode: int
    native_output_root_device: int
    native_output_root_inode: int
    listener_activation_id: str
    listener_invocation_id: str
    listener_pid: int
    listener_start_ticks: int
    listener_socket_device: int
    listener_socket_inode: int
    argv: tuple[str, ...]
    worker_executable_path: str
    worker_argv: tuple[str, ...]
    worker_environment: tuple[tuple[str, str], ...]
    selected_view_sha256: str
    environment: tuple[tuple[str, str], ...]
    expires_monotonic: float
    _selection: RootNativeHermesWorkerSelection = field(repr=False, compare=False)
    _network_projection: Any = field(repr=False, compare=False)
    _runtime_projection: Any = field(repr=False, compare=False)
    _pm_identity: Any = field(repr=False, compare=False)
    _owner: Any = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)
    _selected_view: Any = field(default=None, repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootVerifiedNativeHermesWorkerLaunch(<active held launch>)"

    def close(self) -> None:
        self._owner._release_proof(self)
        self._runtime_projection.close()
        self._pm_identity.close()


class RootActiveNativeHermesWorkerLaunchOwner:
    """Join independent active network, output, PM, and adopted-listener owners."""

    def __init__(self, runtime: Any, listener_receiver: Any, listener_receipt: Any,
                 pm_executable_resolver: Any, *, _seal: object):
        from .active_network_generation import RootActiveNetworkGenerationOwner
        from .active_native_worker_runtime import RootActiveNativeWorkerRuntimeRegistry
        from .committed_pm_executable import RootActiveCommittedPMExecutableResolver
        from .listener_activation import (
            RootActiveAuthorityListenerReceipt,
            RootAuthorityListenerActivationReceiver,
        )
        from .runtime_composition import RootAuthorityRuntime

        network_owner = getattr(getattr(runtime, "service", None),
                                "active_network_generation_owner", None)
        manager = getattr(getattr(runtime, "bindings", None), "process_manager", None)
        if (_seal is not _LAUNCH_SEAL or type(runtime) is not RootAuthorityRuntime
                or runtime.service.root_authority_runtime is not runtime
                or runtime.service.root_runtime_bindings is not runtime.bindings
                or type(network_owner) is not RootActiveNetworkGenerationOwner
                or network_owner._runtime is not runtime
                or type(listener_receiver) is not RootAuthorityListenerActivationReceiver
                or listener_receiver.runtime is not runtime
                or type(listener_receipt) is not RootActiveAuthorityListenerReceipt
                or type(pm_executable_resolver) is not RootActiveCommittedPMExecutableResolver
                or getattr(manager, "_native_worker_launch_owner", None) is not None):
            raise NativeHermesWorkerLaunchUnavailable(
                "exact attached active owners and the manager's one-time composition are required")
        self.runtime = runtime
        self.listener_receiver = listener_receiver
        self.listener_receipt = listener_receipt
        self.network_owner = network_owner
        self.runtime_registry = RootActiveNativeWorkerRuntimeRegistry.from_root_runtime(
            runtime, network_owner)
        self.pm_executable_resolver = pm_executable_resolver
        self.manager = manager
        self._issuer = object()
        self._selections: dict[str, RootNativeHermesWorkerSelection] = {}
        self._proofs: dict[str, RootVerifiedNativeHermesWorkerLaunch] = {}
        self._observed_views: dict[str, RootObservedNativeWorkerView] = {}
        self._gate_member_fds: tuple[int, int] | None = None
        self._lock = threading.RLock()
        self._closed = False
        manager._native_worker_launch_owner = self

    @classmethod
    def from_root_runtime(cls, runtime: Any, listener_receiver: Any,
                          listener_receipt: Any, pm_executable_resolver: Any
                          ) -> "RootActiveNativeHermesWorkerLaunchOwner":
        return cls(runtime, listener_receiver, listener_receipt,
                   pm_executable_resolver, _seal=_LAUNCH_SEAL)

    @_owner_locked
    def select_worker(self, network_id: str, profile_id: str) -> RootNativeHermesWorkerSelection:
        self._require_live()
        self._prune_expired()
        if len(self._selections) >= _MAX_WORKER_SELECTIONS:
            raise NativeHermesWorkerLaunchUnavailable(
                "too many outstanding active worker selections")
        if (not isinstance(network_id, str) or not network_id
                or not isinstance(profile_id, str) or not profile_id):
            raise NativeHermesWorkerLaunchUnavailable("selected network and profile are malformed")
        try:
            projection = self.network_owner.resolve_selected_worker(network_id, profile_id)
            self.network_owner.verify_current(projection)
            if projection.runtime_record.get("execution_mode") != "native-hermes-cli-module-v1":
                raise ValueError("selected active row has no finite Hermes module mode")
            selection = RootNativeHermesWorkerSelection(
                network_id, profile_id, hashlib.sha256(os.urandom(32)).hexdigest(),
                min(projection.expires_monotonic, time.monotonic() + _MAX_TTL),
                projection, self._issuer)
            self._selections[selection.selection_handle] = selection
            return selection
        except Exception:
            raise NativeHermesWorkerLaunchUnavailable(
                "selected active Hermes worker generation is unavailable") from None

    @_owner_locked
    def select_unique_worker_for_profile(self, profile_id: str) -> RootNativeHermesWorkerSelection:
        """Resolve the one protected active network row joined to a profile.

        Root health/task admissions identify a profile through their protected
        enrollment; they do not carry a caller-selected network ID. This
        method derives that ID only from the current sealed catalog and rejects
        absent or ambiguous matches.
        """
        self._require_live()
        catalog = self.runtime.bindings.enrollment_catalog
        if not isinstance(profile_id, str) or not profile_id:
            raise NativeHermesWorkerLaunchUnavailable("selected worker profile is malformed")
        rows = tuple(getattr(catalog, "_active_network_generation_records", {}).values())
        matches = [row for row in rows if row.get("process_profile_id") == profile_id]
        if len(matches) != 1:
            raise NativeHermesWorkerLaunchUnavailable(
                "profile has no unique current native worker network selection")
        row = matches[0]
        if (row.get("network_catalog") != "native_worker_network_records"
                or not isinstance(row.get("network_id"), str)):
            raise NativeHermesWorkerLaunchUnavailable(
                "active catalog row does not select the native worker network")
        return self.select_worker(row["network_id"], profile_id)

    @_owner_locked
    def resolve_gate_runtime(self) -> tuple[Path, Path, str, str]:
        """Hold the exact reviewed helper and isolated installer interpreter.

        An absent final role row is an ordinary unavailable result. This
        method does not invent a role or accept a caller path/digest.
        """
        self._require_live()
        if self._gate_member_fds is not None:
            helper_fd, interpreter_fd = self._gate_member_fds
            try:
                helper, helper_digest = self._verify_gate_member(helper_fd, role="network-startup-helper")
                interpreter, interpreter_digest = self._verify_gate_member(interpreter_fd, role="interpreter")
                return helper, interpreter, helper_digest, interpreter_digest
            except Exception:
                self._close_gate_member_fds()
                raise NativeHermesWorkerLaunchUnavailable(
                    "held installed gate runtime is no longer current") from None
        release = self.runtime.controller_release_receipt
        try:
            from .installer_release import VerifiedInstallerReleaseReceipt
            if type(release) is not VerifiedInstallerReleaseReceipt:
                raise ValueError("verified installed release is unavailable")
            release.verify_current()
            helper_rows = [row for row in release.files
                           if row.relative_path == "helpers/private-loopback-worker-gate.py"
                           and row.roles == ("network-startup-helper",)
                           and row.mode == 0o444 and 0 < row.size_bytes <= 64 * 1024]
            interpreter_rows = [row for row in release.files
                                if row.relative_path == "runtime/bin/python"
                                and row.roles == ("interpreter",)
                                and row.mode & 0o111 and row.size_bytes > 0]
            if len(helper_rows) != 1 or len(interpreter_rows) != 1:
                raise ValueError("exact helper role or installer interpreter is not installed")
            helper_fd = release.open_file(helper_rows[0].artifact_id)
            try:
                interpreter_fd = release.open_file(interpreter_rows[0].artifact_id)
            except BaseException:
                os.close(helper_fd)
                raise
            self._gate_member_fds = (helper_fd, interpreter_fd)
            helper, helper_digest = self._verify_gate_member(helper_fd, role="network-startup-helper")
            interpreter, interpreter_digest = self._verify_gate_member(interpreter_fd, role="interpreter")
            return helper, interpreter, helper_digest, interpreter_digest
        except Exception:
            raise NativeHermesWorkerLaunchUnavailable(
                "exact installed gate helper and isolated interpreter roles are unavailable") from None

    def _verify_gate_member(self, fd: int, *, role: str) -> tuple[Path, str]:
        from .installer_release import VerifiedInstallerReleaseReceipt
        release = self.runtime.controller_release_receipt
        if type(release) is not VerifiedInstallerReleaseReceipt:
            raise ValueError("release receipt changed")
        release.verify_current()
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o222:
            raise ValueError("held gate member is writable or not regular")
        candidates = [row for row in release.files
                      if row.roles == (role,)
                      and row.device == info.st_dev and row.inode == info.st_ino
                      and row.size_bytes == info.st_size]
        if role == "network-startup-helper":
            candidates = [row for row in candidates
                          if row.relative_path == "helpers/private-loopback-worker-gate.py"]
        else:
            candidates = [row for row in candidates
                          if row.relative_path == "runtime/bin/python"]
        if len(candidates) != 1:
            raise ValueError("held gate role does not match one installed release member")
        digest = hashlib.sha256()
        offset = 0
        while offset < info.st_size:
            block = os.pread(fd, min(128 * 1024, info.st_size - offset), offset)
            if not block:
                raise ValueError("held gate member was truncated")
            digest.update(block)
            offset += len(block)
        if digest.hexdigest() != candidates[0].sha256:
            raise ValueError("held gate member bytes changed")
        return release.release_root / candidates[0].relative_path, digest.hexdigest()

    def _close_gate_member_fds(self) -> None:
        fds, self._gate_member_fds = self._gate_member_fds, None
        if fds is not None:
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass

    @_owner_locked
    def resolve_selected_native_worker_launch(
            self, selection: RootNativeHermesWorkerSelection
            ) -> RootVerifiedNativeHermesWorkerLaunch:
        self._require_selection(selection)
        self._prune_expired()
        if len(self._proofs) >= _MAX_LAUNCH_PROOFS:
            raise NativeHermesWorkerLaunchUnavailable(
                "too many outstanding active worker launch proofs")
        runtime_projection = None
        pm_identity = None
        try:
            network = selection._network_projection
            self.network_owner.verify_current(network)
            row = network.runtime_record
            if row.get("execution_mode") != "native-hermes-cli-module-v1":
                raise ValueError("active runtime row is not the exact native module mode")
            from .native_worker_start_recipe import ARGV_SUFFIX
            if tuple(ARGV_SUFFIX) != (
                    "-m", "hermes_cli.main", "chat", "--query-file", "-", "--oneshot", "--quiet"):
                raise ValueError("fixed reviewed CLI recipe changed")
            runtime_projection = self.runtime_registry.resolve_current(network)
            pm_identity = self.pm_executable_resolver.resolve_selected()
            receiver = self.listener_receiver
            listener = receiver.observe_active_current(self.listener_receipt)
            profile = self.manager.profiles.get(selection.profile_id)
            executable = pm_identity.executable_path
            executable_info = os.stat(executable, follow_symlinks=False)
            if (type(profile) is not __import__(
                    "hermes_installer.managed_process_custodian",
                    fromlist=["ManagedProfileCustody"]).ManagedProfileCustody
                    or profile.profile_id != selection.profile_id
                    or profile.generation != network.profile_generation
                    or Path(profile.executable) != executable
                    or profile.artifact_sha256 != pm_identity.executable_sha256
                    or profile.service_generation_digest != network.service_generation_digest
                    or pm_identity.network_id != network.network_id
                    or pm_identity.profile_id != network.process_profile_id
                    or pm_identity.service_generation_digest != network.service_generation_digest
                    or pm_identity.publication_receipt_handle != network.publication_receipt_handle
                    or pm_identity.publication_sha256 != network.publication_sha256
                    or pm_identity.active_generation_id != network.active_record["generation_id"]
                    or pm_identity.runtime_record_id != row["id"]
                    or pm_identity.runtime_record_sha256 != network.active_record["worker_runtime_record_sha256"]
                    or pm_identity.pm_runtime_receipt_handle != row["pm_runtime_receipt_handle"]
                    or pm_identity.runtime_closure_sha256
                       != row["committed_venv_identity"]["runtime_closure_sha256"]
                    or (executable_info.st_dev, executable_info.st_ino, executable_info.st_uid,
                        executable_info.st_gid, stat.S_IMODE(executable_info.st_mode))
                       != (pm_identity.executable_device, pm_identity.executable_inode,
                           pm_identity.executable_uid, pm_identity.executable_gid,
                           pm_identity.executable_mode)
                    or runtime_projection.runtime_record_id != row["id"]
                    or runtime_projection.runtime_record_sha256
                       != network.active_record["worker_runtime_record_sha256"]
                    or runtime_projection.pm_runtime_receipt_handle != row["pm_runtime_receipt_handle"]
                    or listener.publication_receipt_handle != network.publication_receipt_handle
                    or listener.publication_sha256 != network.publication_sha256
                    or listener.service_generation_digest != network.service_generation_digest
                    or listener.socket_inode <= 0):
                raise ValueError("current network, PM, listener, profile, or runtime row does not join")
            expiry = min(network.expires_monotonic, runtime_projection.expires_monotonic,
                         pm_identity.expires_monotonic, listener.expires_monotonic)
            if expiry <= time.monotonic():
                raise ValueError("current source or listener lease has expired")
            worker_relative = Path(pm_identity.runtime_relative).relative_to(
                Path(pm_identity.runtime_venv_relative)).as_posix()
            if worker_relative in {"", "."} or worker_relative.startswith("../"):
                raise ValueError("committed Python executable has no safe venv-relative path")
            worker_executable = "/hermes/.native/pm/" + worker_relative
            worker_argv = (worker_executable, *ARGV_SUFFIX)
            worker_environment = (("HOME", "/hermes"), ("HERMES_HOME", "/hermes"))
            proof = RootVerifiedNativeHermesWorkerLaunch(
                launch_handle=hashlib.sha256(os.urandom(32)).hexdigest(),
                network_id=network.network_id, profile_id=profile.profile_id,
                profile_generation=profile.generation,
                service_generation_digest=network.service_generation_digest,
                publication_receipt_handle=network.publication_receipt_handle,
                publication_sha256=network.publication_sha256,
                active_generation_id=network.active_record["generation_id"],
                source_choice_signed_record_sha256=network.source_choice_signed_record_sha256,
                runtime_record_id=row["id"],
                runtime_record_sha256=network.active_record["worker_runtime_record_sha256"],
                pm_runtime_receipt_handle=pm_identity.pm_runtime_receipt_handle,
                pm_runtime_closure_sha256=pm_identity.runtime_closure_sha256,
                executable_path=executable, executable_sha256=pm_identity.executable_sha256,
                executable_device=pm_identity.executable_device,
                executable_inode=pm_identity.executable_inode,
                executable_uid=pm_identity.executable_uid,
                executable_gid=pm_identity.executable_gid,
                executable_mode=pm_identity.executable_mode,
                native_output_root_device=runtime_projection.native_output_root_device,
                native_output_root_inode=runtime_projection.native_output_root_inode,
                listener_activation_id=listener.activation_id,
                listener_invocation_id=listener.daemon_invocation_id,
                listener_pid=listener.daemon_pid,
                listener_start_ticks=listener.daemon_start_ticks,
                listener_socket_device=listener.socket_device,
                listener_socket_inode=listener.socket_inode,
                argv=(str(executable), *ARGV_SUFFIX),
                worker_executable_path=worker_executable,
                worker_argv=worker_argv,
                worker_environment=worker_environment,
                selected_view_sha256="",
                environment=(("HOME", "/hermes"), ("HERMES_HOME", "/hermes")),
                expires_monotonic=expiry, _selection=selection,
                _network_projection=network, _runtime_projection=runtime_projection,
                _pm_identity=pm_identity, _owner=self, _issuer=self._issuer,
            )
            self._proofs[proof.launch_handle] = proof
            return proof
        except Exception:
            if runtime_projection is not None:
                runtime_projection.close()
            if pm_identity is not None:
                pm_identity.close()
            raise NativeHermesWorkerLaunchUnavailable(
                "current active source, PM closure, and adopted authority listener do not prove this launch") from None

    @_owner_locked
    def verify_current_native_worker_launch(
            self, proof: RootVerifiedNativeHermesWorkerLaunch
            ) -> RootVerifiedNativeHermesWorkerLaunch:
        self._require_live()
        if (type(proof) is not RootVerifiedNativeHermesWorkerLaunch
                or proof._issuer is not self._issuer
                or self._proofs.get(proof.launch_handle) is not proof
                or proof.expires_monotonic <= time.monotonic()):
            raise NativeHermesWorkerLaunchUnavailable("native worker launch proof is foreign or stale")
        current = self.resolve_selected_native_worker_launch(proof._selection)
        try:
            comparable = (
                "network_id", "profile_id", "profile_generation", "service_generation_digest",
                "publication_receipt_handle", "publication_sha256", "active_generation_id",
                "source_choice_signed_record_sha256", "runtime_record_id", "runtime_record_sha256",
                "pm_runtime_receipt_handle", "pm_runtime_closure_sha256", "executable_path",
                "executable_sha256", "executable_device", "executable_inode", "executable_uid",
                "executable_gid", "executable_mode", "native_output_root_device",
                "native_output_root_inode", "listener_activation_id", "listener_invocation_id",
                "listener_pid", "listener_start_ticks", "listener_socket_device",
                "listener_socket_inode", "argv", "environment",
                "worker_executable_path", "worker_argv", "worker_environment",
            )
            if any(getattr(proof, name) != getattr(current, name) for name in comparable):
                raise NativeHermesWorkerLaunchUnavailable("active launch joins changed after proof issuance")
            if proof._selected_view is not None:
                view = proof._selected_view
                if (type(view) is not RootSelectedNativeWorkerView
                        or view._issuer is not self._issuer
                        or view._launch_handle != proof.launch_handle
                        or view.selected_view_sha256 != proof.selected_view_sha256):
                    raise NativeHermesWorkerLaunchUnavailable("selected worker view is foreign or changed")
            self.network_owner.verify_current(proof._network_projection)
            self.runtime_registry.verify_current(proof._runtime_projection)
            self.pm_executable_resolver.verify_current(proof._pm_identity)
            listener_now = self.listener_receiver.observe_active_current(self.listener_receipt)
            if (listener_now.activation_id != proof.listener_activation_id
                    or listener_now.daemon_invocation_id != proof.listener_invocation_id
                    or listener_now.daemon_pid != proof.listener_pid
                    or listener_now.daemon_start_ticks != proof.listener_start_ticks
                    or listener_now.socket_device != proof.listener_socket_device
                    or listener_now.socket_inode != proof.listener_socket_inode):
                raise NativeHermesWorkerLaunchUnavailable("adopted listener identity changed")
            return proof
        finally:
            current.close()
            self._proofs.pop(current.launch_handle, None)

    @_owner_locked
    def attach_selected_worker_view(self, proof: RootVerifiedNativeHermesWorkerLaunch,
                                    view: RootSelectedNativeWorkerView
                                    ) -> RootVerifiedNativeHermesWorkerLaunch:
        """Bind one exact manager-materialized mount view to its held proof."""
        self._require_live()
        if (type(proof) is not RootVerifiedNativeHermesWorkerLaunch
                or proof._issuer is not self._issuer
                or self._proofs.get(proof.launch_handle) is not proof
                or proof._selected_view is not None or proof.selected_view_sha256
                or type(view) is not RootSelectedNativeWorkerView
                or view._issuer is not self._issuer
                or view._launch_handle != proof.launch_handle
                or view.worker_executable_path != proof.worker_executable_path
                or view.worker_argv != proof.worker_argv
                or view.worker_environment != proof.worker_environment
                or not re.fullmatch(r"[0-9a-f]{64}", view.selected_view_sha256)):
            raise NativeHermesWorkerLaunchUnavailable(
                "selected worker mount view is foreign, stale, or already attached")
        self.verify_current_native_worker_launch(proof)
        object.__setattr__(proof, "selected_view_sha256", view.selected_view_sha256)
        object.__setattr__(proof, "_selected_view", view)
        return proof

    @_owner_locked
    def resolve_selected_native_worker_view(
            self, proof: RootVerifiedNativeHermesWorkerLaunch) -> RootSelectedNativeWorkerView:
        self.verify_current_native_worker_launch(proof)
        view = getattr(proof, "_selected_view", None)
        if (type(view) is not RootSelectedNativeWorkerView
                or view._issuer is not self._issuer
                or view._launch_handle != proof.launch_handle
                or view.selected_view_sha256 != proof.selected_view_sha256):
            raise NativeHermesWorkerLaunchUnavailable("selected native worker view is not owner-issued")
        return view

    @_owner_locked
    def issue_observed_native_worker_view(
            self, proof: RootVerifiedNativeHermesWorkerLaunch, *, process_id: str,
            process_pid: int, process_start_ticks: int, cgroup_identity: str,
            process_uid: int, process_gid: int, mount_namespace_inode: int,
            network_namespace_inode: int, observed_monotonic: float
            ) -> RootObservedNativeWorkerView:
        self.verify_current_native_worker_launch(proof)
        self._prune_observed_views()
        view = proof._selected_view
        if (type(view) is not RootSelectedNativeWorkerView
                or not re.fullmatch(r"[0-9a-f]{32}", process_id)
                or type(process_pid) is not int or process_pid <= 0
                or type(process_start_ticks) is not int or process_start_ticks <= 0
                or not isinstance(cgroup_identity, str)
                or not cgroup_identity.startswith("/system.slice/")
                or type(process_uid) is not int or process_uid <= 0
                or type(process_gid) is not int or process_gid < 0
                or type(mount_namespace_inode) is not int or mount_namespace_inode <= 0
                or type(network_namespace_inode) is not int or network_namespace_inode <= 0
                or not isinstance(observed_monotonic, (int, float))
                or isinstance(observed_monotonic, bool)
                or observed_monotonic < 0
                or len(self._observed_views) >= 16):
            raise NativeHermesWorkerLaunchUnavailable("observed worker view is malformed or capacity is exhausted")
        observation = RootObservedNativeWorkerView(
            schema=1, observation_handle=secrets.token_hex(16),
            launch_handle=proof.launch_handle, process_id=process_id,
            process_pid=process_pid, process_start_ticks=process_start_ticks,
            cgroup_identity=cgroup_identity, process_uid=process_uid,
            process_gid=process_gid, mount_namespace_inode=mount_namespace_inode,
            network_namespace_inode=network_namespace_inode,
            selected_view_sha256=view.selected_view_sha256,
            observed_monotonic=float(observed_monotonic),
            expires_monotonic=min(proof.expires_monotonic, float(observed_monotonic) + _MAX_TTL),
            _issuer=self._issuer,
        )
        self._observed_views[observation.observation_handle] = observation
        return observation

    @_owner_locked
    def verify_current_observed_native_worker_view(
            self, proof: RootVerifiedNativeHermesWorkerLaunch,
            observed: RootObservedNativeWorkerView) -> RootObservedNativeWorkerView:
        self.verify_current_native_worker_launch(proof)
        if (type(observed) is not RootObservedNativeWorkerView
                or observed._issuer is not self._issuer
                or self._observed_views.get(observed.observation_handle) is not observed
                or observed.launch_handle != proof.launch_handle
                or observed.selected_view_sha256 != proof.selected_view_sha256
                or observed.expires_monotonic <= time.monotonic()):
            raise NativeHermesWorkerLaunchUnavailable("observed worker view is foreign or stale")
        return observed

    @_owner_locked
    def retire_observed_native_worker_view(self, observed: RootObservedNativeWorkerView) -> None:
        if (type(observed) is RootObservedNativeWorkerView
                and observed._issuer is self._issuer
                and self._observed_views.get(observed.observation_handle) is observed):
            self._observed_views.pop(observed.observation_handle, None)

    @_owner_locked
    def _prune_observed_views(self) -> None:
        now = time.monotonic()
        for handle, observed in tuple(self._observed_views.items()):
            if observed.expires_monotonic <= now:
                self._observed_views.pop(handle, None)

    @_owner_locked
    def close(self) -> None:
        self._closed = True
        self._close_gate_member_fds()
        for proof in tuple(self._proofs.values()):
            proof.close()
        self._proofs.clear()
        self._observed_views.clear()
        self._selections.clear()
        self.runtime_registry.close()

    @_owner_locked
    def _release_proof(self, proof: RootVerifiedNativeHermesWorkerLaunch) -> None:
        if (type(proof) is RootVerifiedNativeHermesWorkerLaunch
                and proof._issuer is self._issuer
            and self._proofs.get(proof.launch_handle) is proof):
            self._proofs.pop(proof.launch_handle, None)
            self._prune_selections()

    @_owner_locked
    def _prune_expired(self) -> None:
        expired = [proof for proof in self._proofs.values()
                   if proof.expires_monotonic <= time.monotonic()]
        for proof in expired:
            proof.close()
        self._prune_selections()

    @_owner_locked
    def _prune_selections(self) -> None:
        now = time.monotonic()
        for handle, selection in tuple(self._selections.items()):
            # A selected handle must survive the brief caller-to-proof gap.
            # It is bounded by its own short projection expiry and explicit
            # lifecycle release after the process-start attempt.
            if selection.expires_monotonic > now:
                continue
            self._selections.pop(handle, None)
            retire = getattr(self.network_owner, "retire_selected_worker_projection", None)
            if callable(retire):
                retire(selection._network_projection)

    @_owner_locked
    def release_selection(self, selection: RootNativeHermesWorkerSelection) -> None:
        """Retire a completed no-proof selection and its network projection."""
        if (type(selection) is not RootNativeHermesWorkerSelection
                or selection._issuer is not self._issuer
                or self._selections.get(selection.selection_handle) is not selection
                or any(proof._selection is selection for proof in self._proofs.values())):
            raise NativeHermesWorkerLaunchUnavailable(
                "selection is foreign or still retained by a live launch proof")
        self._selections.pop(selection.selection_handle, None)
        self.network_owner.retire_selected_worker_projection(selection._network_projection)

    @_owner_locked
    def _require_selection(self, selection: Any) -> None:
        self._require_live()
        if (type(selection) is not RootNativeHermesWorkerSelection
                or selection._issuer is not self._issuer
                or self._selections.get(selection.selection_handle) is not selection
                or selection.expires_monotonic <= time.monotonic()
                or selection.network_id != selection._network_projection.network_id
                or selection.profile_id != selection._network_projection.process_profile_id):
            raise NativeHermesWorkerLaunchUnavailable("worker selection is not an owner-issued active member")

    def _require_live(self) -> None:
        if self._closed or self.runtime.service.root_authority_runtime is not self.runtime:
            raise NativeHermesWorkerLaunchUnavailable("active native worker launch owner is closed or detached")
        if self.runtime.service.root_runtime_bindings is not self.runtime.bindings:
            self.close()
            raise NativeHermesWorkerLaunchUnavailable("active root bindings changed")


_LAUNCH_SEAL = object()
_MAX_LAUNCH_PROOFS = 4
_MAX_WORKER_SELECTIONS = 4
_MAX_TTL = 30.0


def preload_native_worker_launch_closure() -> None:
    """Load the finite launch/currentness source before actor capture."""
    for module in (
        "hermes_installer.authority.active_network_generation",
        "hermes_installer.authority.active_native_worker_runtime",
        "hermes_installer.authority.committed_pm_executable",
        "hermes_installer.authority.listener_activation",
        "hermes_installer.authority.native_health_source",
        "hermes_installer.authority.native_health_observer",
        "hermes_installer.authority.functional_health_receipt_consumer",
        "hermes_installer.authority.native_worker_recipes",
        "hermes_installer.authority.native_worker_runtime_materialization",
        "hermes_installer.authority.native_worker_start_recipe",
        "hermes_installer.authority.native_health_observer",
        "hermes_installer.authority.native_health_daemon",
        "hermes_installer.authority.native_input_observer",
        "hermes_installer.authority.host_tool_observation",
        "hermes_installer.authority.runtime_composition",
    ):
        importlib.import_module(module)

__all__ = [
    "NativeHermesWorkerLaunchUnavailable", "RootActiveNativeHermesWorkerLaunchOwner",
    "RootNativeHermesWorkerSelection", "RootVerifiedNativeHermesWorkerLaunch",
    "RootSelectedNativeWorkerView", "RootSelectedNativeWorkerViewMount",
    "RootObservedNativeWorkerView",
    "preload_native_worker_launch_closure",
]
