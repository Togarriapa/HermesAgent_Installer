"""Root-owned native loader observations and package custody proofs.

The manager's mount receipt establishes immutable mounted bytes. This module
adds the selected loader's private progress channel, checks that the event came
from the live manager-owned child, and joins it to the current mount and active
package catalog. It is intentionally not an Authority RPC surface.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import select
import socket
import stat
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from .types import AuthorityDenied, HostContext, canonical_digest

MAX_PROGRESS_BYTES = 65_536
MAX_ACTIONS = 256
MAX_LAUNCH_LEASE_SECONDS = 600.0
_FRAME_HEADER = struct.Struct("!I")
_PROGRESS_FIELDS = frozenset({
    "schema", "launch_nonce", "sequence", "phase", "package_id", "generation",
    "package_generation",
    "entrypoint_sha256", "resolver_sha256", "registered_registration_ids",
    "loaded_process_roles",
})
_PHASES = ("entrypoint-imported", "actions-registered", "ready")
_DIGEST_FIELDS = ("entrypoint_sha256", "resolver_sha256")


@dataclass(frozen=True, slots=True)
class NativeLoaderSelection:
    """Digest-bound loader/package selection returned by the active root catalog."""

    process_id: str
    package_id: str
    profile_id: str
    generation: str
    package_generation: str
    compiled_closure_sha256: str
    entrypoint_sha256: str
    resolver_sha256: str
    service_generation_digest: str
    loader_role_artifact_id: str
    loader_role_sha256: str
    registered_action_ids: tuple[str, ...]
    registered_registration_ids: tuple[str, ...] = ()
    observer_role_action_bindings: tuple[tuple[str, str, str, str], ...] = ()
    process_roles: tuple["NativeProcessRoleSelection", ...] = ()

    def __post_init__(self) -> None:
        for name in ("process_id", "package_id", "profile_id", "generation", "package_generation",
                     "loader_role_artifact_id"):
            _identifier(getattr(self, name), name)
        for name in ("compiled_closure_sha256", "entrypoint_sha256", "resolver_sha256",
                     "service_generation_digest", "loader_role_sha256"):
            _digest(getattr(self, name), name)
        if (not isinstance(self.registered_action_ids, tuple)
                or not 1 <= len(self.registered_action_ids) <= MAX_ACTIONS
                or any(not isinstance(item, str) or not item for item in self.registered_action_ids)
                or tuple(sorted(set(self.registered_action_ids))) != self.registered_action_ids):
            raise ValueError("selected native actions must be a bounded sorted unique tuple")
        if (not isinstance(self.registered_registration_ids, tuple)
                or not 1 <= len(self.registered_registration_ids) <= MAX_ACTIONS
                or any(not _identifier_value(item) for item in self.registered_registration_ids)
                or tuple(sorted(set(self.registered_registration_ids)))
                    != self.registered_registration_ids):
            raise ValueError("selected native registrations must be a bounded sorted unique tuple")
        bindings = self.observer_role_action_bindings
        if (not isinstance(bindings, tuple) or len(bindings) > MAX_ACTIONS
                or any(not isinstance(item, tuple) or len(item) != 4
                       or not all(isinstance(value, str) and value for value in item)
                       or not _valid_digest(item[2]) for item in bindings)
                or tuple(sorted(set(bindings))) != bindings):
            raise ValueError("selected observer roles must be bounded sorted root catalog bindings")
        if (not isinstance(self.process_roles, tuple) or len(self.process_roles) > MAX_ACTIONS
                or any(not isinstance(item, NativeProcessRoleSelection) for item in self.process_roles)
                or tuple(sorted(item.role_id for item in self.process_roles))
                    != tuple(item.role_id for item in self.process_roles)):
            raise ValueError("selected process roles must be a bounded sorted tuple")
        if any(item.profile_generation != self.generation
               or item.native_package_generation != self.package_generation
               for item in self.process_roles):
            raise ValueError("selected process role generations differ from the active process/package pair")
        selected_role_ids = {item.role_id for item in self.process_roles}
        if any(role_id not in selected_role_ids or action_id not in self.registered_action_ids
               for role_id, _artifact_id, _sha256, action_id in bindings):
            raise ValueError("selected observer role action is absent from its independent role/action tables")


@dataclass(frozen=True, slots=True)
class NativeProcessRoleSelection:
    """Protected process-role catalog identity, separate from adapter actions."""

    role_id: str
    role_artifact_id: str
    role_sha256: str
    profile_generation: str
    native_package_generation: str
    role_source_receipt_handle: str
    module_name: str
    closure_member_path: str
    role_source_revision: str
    role_source_tree_sha256: str
    registration_ids: tuple[str, ...]
    action_binding_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("role_id", "role_artifact_id", "profile_generation",
                     "native_package_generation", "role_source_receipt_handle"):
            _identifier(getattr(self, name), name)
        for name in ("role_sha256", "role_source_tree_sha256"):
            _digest(getattr(self, name), name)
        member = self.closure_member_path
        parts = PurePosixPath(member).parts if isinstance(member, str) else ()
        if (not isinstance(self.module_name, str)
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", self.module_name)
                or not isinstance(member, str) or not member or "\\" in member
                or PurePosixPath(member).is_absolute() or not parts
                or any(part in {"", ".", ".."} for part in parts)
                or PurePosixPath(member).as_posix() != member
                or not isinstance(self.role_source_revision, str) or not self.role_source_revision
                or any(ord(char) < 0x20 for char in self.role_source_revision)):
            raise ValueError("selected process-role module provenance is invalid")
        for name in ("registration_ids", "action_binding_ids"):
            values = getattr(self, name)
            if (not isinstance(values, tuple) or len(values) > MAX_ACTIONS
                    or any(not _identifier_value(value) for value in values)
                    or tuple(sorted(set(values))) != values):
                raise ValueError(f"selected process role {name} must be bounded and unique")


@dataclass(frozen=True, slots=True)
class LivePeerProcess:
    """A root-authenticated RPC peer and its borrowed PIDFD."""

    pid: int
    pidfd: int
    identity: Any


@dataclass(frozen=True, slots=True)
class LoadedPackageClosureProof:
    """Immutable DTO matching planning/protected-runtime-assembly-contract.json."""

    schema: int
    proof_id: str
    package_id: str
    profile_id: str
    generation: str
    compiled_closure_sha256: str
    entrypoint_sha256: str
    resolver_sha256: str
    mount_namespace_inode: int
    mount_id: str
    mount_target_digest: str
    mount_flags: tuple[str, ...]
    source_root_device: int
    source_root_inode: int
    target_peer_identity: Any
    loader_role_artifact_id: str
    loader_role_sha256: str
    loader_ready_event_id: str
    observed_entrypoint_action_ids: tuple[str, ...]
    issued_monotonic: float
    expires_monotonic: float
    service_generation_digest: str
    role_id: str
    role_source_receipt_handle: str
    role_module_name: str
    role_closure_member_path: str
    role_source_revision: str
    role_source_tree_sha256: str
    role_module_device: int
    role_module_inode: int
    role_module_sha256: str
    role_module_size_bytes: int
    observed_registration_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LoadedProcessRoleObservation:
    """Loader-channel observation of an imported protected process-role module."""

    role_id: str
    module_name: str
    closure_member_path: str
    module_file_sha256: str
    module_file_device: int
    module_file_inode: int
    module_file_size_bytes: int

    def __post_init__(self) -> None:
        if (not _identifier_value(self.role_id)
                or not isinstance(self.module_name, str)
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", self.module_name)):
            raise ValueError("observed process-role module identity is invalid")
        member = self.closure_member_path
        parts = PurePosixPath(member).parts if isinstance(member, str) else ()
        if (not isinstance(member, str) or not member or "\\" in member
                or PurePosixPath(member).is_absolute() or not parts
                or any(part in {"", ".", ".."} for part in parts)
                or PurePosixPath(member).as_posix() != member):
            raise ValueError("observed process-role closure path is invalid")
        if (type(self.module_file_device) is not int or self.module_file_device < 0
                or type(self.module_file_inode) is not int or self.module_file_inode <= 0
                or type(self.module_file_size_bytes) is not int
                or not 0 <= self.module_file_size_bytes <= 16 * 1024 * 1024):
            raise ValueError("observed process-role inode identity is invalid")
        _digest(self.module_file_sha256, "observed process-role module digest")


@dataclass(frozen=True, slots=True)
class ResolvedTargetPeer:
    """Current source recipient with a PIDFD duplicate owned by the caller."""

    pid: int
    pidfd: int
    uid: int
    profile_id: str
    generation: str
    identity: Any


@dataclass(frozen=True, slots=True)
class LiveNativeInputTarget:
    """Root-selected initial native input target with an owned PIDFD duplicate.

    The target is not a source receipt or effect grant. Its ``pidfd`` belongs
    to the caller and must be closed after input observation completes.
    """

    schema: int
    process_id: str
    profile_id: str
    generation: str
    peer_pid: int
    peer_pidfd: int
    live_peer_identity: Any
    loaded_package_proof: LoadedPackageClosureProof
    service_generation_digest: str
    expires_monotonic: float


class RootNativeInputTargetResolver:
    """Resolve an initial-input target from an exact root execution selection.

    The selection registry validates the complete admission/process join and
    returns its exact current DTO. The process manager then resolves the
    manager-issued ``ManagedTaskHandle`` to a current process lease; no PID or
    profile selector is accepted here. The active observer row and the store's
    root-observed loaded-package proof complete the input target.
    """

    def __init__(self, *, selection_registry: Any, custody_resolver: Any,
                 observer_enrollments: Mapping[str, Any],
                 loader_observations: "RootNativeLoaderObservationStore"):
        from .source_observers import SourceObserverEnrollment

        if (not callable(getattr(selection_registry, "resolve_current_execution", None))
                or not callable(getattr(custody_resolver, "resolve_managed_task_process_handle", None))
                or not callable(getattr(custody_resolver, "resolve_owned_process_handle", None))
                or not callable(getattr(custody_resolver, "resolve_live_peer", None))
                or not isinstance(observer_enrollments, Mapping) or not observer_enrollments
                or not isinstance(loader_observations, RootNativeLoaderObservationStore)
                or any(not isinstance(key, str) or not isinstance(value, SourceObserverEnrollment)
                       or key != value.observer_enrollment_id
                       for key, value in observer_enrollments.items())):
            raise ValueError("native input target requires the active task registry, custody lease, and observer joins")
        self.selection_registry = selection_registry
        self.custody_resolver = custody_resolver
        self.observer_enrollments = dict(observer_enrollments)
        self.loader_observations = loader_observations

    def resolve_selected_native_input_target(self, selected_execution: Any) -> LiveNativeInputTarget:
        """Resolve the exact root-selected task/health/Desktop native peer.

        ``resolve_current_execution`` is a non-consuming root-registry lookup:
        it rejects fabricated/stale DTOs and returns the exact active selection
        only after rechecking its admission and process-handle join.
        """
        resolver = self.selection_registry.resolve_current_execution
        try:
            selected = resolver(selected_execution)
        except Exception:
            raise AuthorityDenied("native.input.selection", "root native execution selection is stale") from None
        if selected is None or selected is not selected_execution:
            raise AuthorityDenied("native.input.selection", "root native execution selection is unavailable")
        required_text = (
            "selection_handle", "kind", "profile_id", "generation",
            "native_package_id", "native_package_generation", "observer_enrollment_id",
            "source_action_id", "service_generation_digest",
        )
        if (getattr(selected, "schema", None) != 1
                or any(not isinstance(getattr(selected, name, None), str)
                       or not getattr(selected, name) for name in required_text)
                or selected.kind not in {"resource-task", "native-health", "desktop-input"}
                or type(getattr(selected, "expires_monotonic", None)) not in (int, float)
                or not math.isfinite(selected.expires_monotonic)
                or self.loader_observations.clock() >= selected.expires_monotonic):
            raise AuthorityDenied("native.input.selection", "root native execution selection is malformed or expired")
        observer = self.observer_enrollments.get(selected.observer_enrollment_id)
        if (observer is None or observer.source_kind != "native-input"
                or observer.profile_id != selected.profile_id
                or observer.generation != selected.generation
                or observer.package_id != selected.native_package_id
                or observer.source_action_id != selected.source_action_id):
            raise AuthorityDenied("native.input.observer", "selected execution has no exact active input observer")
        process_handle = getattr(selected, "process_handle", None)
        if (getattr(selected, "execution_handle", None) is None
                or process_handle is None):
            raise AuthorityDenied("native.input.process", "selected execution has no manager task handle")
        try:
            if selected.kind == "resource-task":
                lease = self.custody_resolver.resolve_managed_task_process_handle(process_handle)
            else:
                lease = self.custody_resolver.resolve_owned_process_handle(process_handle)
        except Exception:
            raise AuthorityDenied("native.input.process", "selected manager task is no longer active") from None
        if lease is None:
            raise AuthorityDenied("native.input.process", "selected manager task has no active process lease")
        target_fd = -1
        try:
            now = self.loader_observations.clock()
            peer_pid = getattr(lease, "pid", None)
            borrowed_pidfd = getattr(lease, "pidfd", None)
            process_id = getattr(lease, "process_id", None)
            lease_profile = getattr(lease, "profile_id", None)
            lease_generation = getattr(lease, "generation", None)
            lease_expiry = getattr(lease, "expires_monotonic", None)
            if (process_id != process_handle.process_id
                    or lease_profile != selected.profile_id
                    or lease_generation != selected.generation
                    or type(peer_pid) is not int or peer_pid <= 0
                    or type(borrowed_pidfd) is not int or borrowed_pidfd < 0
                    or type(lease_expiry) not in (int, float)
                    or not math.isfinite(lease_expiry)
                    or not now < lease_expiry):
                raise AuthorityDenied("native.input.process", "selected task process lease differs from its root join")
            identity = self.custody_resolver.resolve_live_peer(
                peer_pid, borrowed_pidfd, profile_id=selected.profile_id,
                generation=selected.generation,
            )
            if (identity is None
                    or getattr(identity, "profile_id", None) != selected.profile_id
                    or getattr(identity, "generation", None) != selected.generation
                    or getattr(identity, "kernel_uid", None) != getattr(lease, "uid", None)
                    or getattr(identity, "start_ticks", None) != getattr(lease, "start_ticks", None)
                    or getattr(identity, "cgroup_identity", None) != getattr(lease, "cgroup_identity", None)
                    or getattr(identity, "namespace_identity", None) != (
                        f"mnt:{getattr(lease, 'mount_namespace_inode', None)};"
                        f"net:{getattr(lease, 'network_namespace_inode', None)}")
                    or getattr(identity, "executable_sha256", None) != getattr(lease, "executable_sha256", None)):
                raise AuthorityDenied("native.input.process", "selected task kernel identity is stale or substituted")
            target_fd = os.dup(borrowed_pidfd)
            if (RootNativeLoaderObservationStore._pidfd_target(target_fd) != peer_pid
                    or RootNativeLoaderObservationStore._pidfd_exited(target_fd)):
                raise AuthorityDenied("native.input.process", "selected task exited while its PIDFD was retained")
            retained_identity = self.custody_resolver.resolve_live_peer(
                peer_pid, target_fd, profile_id=selected.profile_id,
                generation=selected.generation,
            )
            if retained_identity is None or retained_identity != identity:
                raise AuthorityDenied("native.input.process", "selected task changed while its PIDFD was retained")
            proof = self.loader_observations.resolve_loaded_package_closure(
                LivePeerProcess(peer_pid, target_fd, retained_identity), observer,
            )
            if (not isinstance(proof, LoadedPackageClosureProof)
                    or proof.profile_id != selected.profile_id
                    or proof.generation != selected.generation
                    or proof.package_id != selected.native_package_id
                    or proof.service_generation_digest != selected.service_generation_digest
                    or proof.target_peer_identity != retained_identity
                    or proof.expires_monotonic <= now):
                raise AuthorityDenied("native.input.closure", "selected task lacks its exact current loaded-package proof")
            expiry = min(float(selected.expires_monotonic), float(lease_expiry),
                         float(proof.expires_monotonic))
            if not now < expiry:
                raise AuthorityDenied("native.input.expired", "selected native input target has no remaining lease")
            result = LiveNativeInputTarget(
                schema=1, process_id=process_id, profile_id=selected.profile_id,
                generation=selected.generation, peer_pid=peer_pid, peer_pidfd=target_fd,
                live_peer_identity=retained_identity, loaded_package_proof=proof,
                service_generation_digest=selected.service_generation_digest,
                expires_monotonic=expiry,
            )
            target_fd = -1
            return result
        finally:
            if target_fd >= 0:
                try:
                    os.close(target_fd)
                except OSError:
                    pass
            close = getattr(lease, "close", None)
            if callable(close):
                close()


def native_bridge_source_target_selector(broker: Any,
                                          clock: Callable[[], float] = time.monotonic
                                          ) -> Callable[[Any, HostContext], Any]:
    """Build the strict HI11 counterpart selector from root pending-pair state.

    ``NativeBridgeBroker.resolve_pending_pair_for_context`` returns a private
    DTO with fresh producer/gateway PIDFD duplicates. The explicit protected
    observer-to-delivery-role mapping is authoritative; role, target and
    recipient strings are never interpreted to choose a peer.
    """
    resolver = getattr(broker, "resolve_pending_pair_for_context", None)
    if not callable(resolver) or not callable(clock):
        raise ValueError("native source targets require the root pending-pair resolver")

    def select(observer: Any, parent_context: HostContext) -> Any:
        if not isinstance(parent_context, HostContext):
            raise AuthorityDenied("source.target", "signed root parent context is unavailable")
        pair = resolver(parent_context)
        producer = getattr(pair, "producer", None)
        gateway = getattr(pair, "gateway", None)
        try:
            _validate_pending_native_pair(pair, parent_context, observer, clock())
            _validate_pending_peer(producer, custody=None)
            _validate_pending_peer(gateway, custody=None)
            if (producer.role != "producer" or gateway.role != "gateway"
                    or producer.pid == gateway.pid or producer.pidfd == gateway.pidfd):
                raise AuthorityDenied("source.target", "pending pair does not contain distinct role-bound peers")
            bindings = tuple(pair.observer_delivery_bindings)
            matching = [item for item in bindings
                        if getattr(item, "observer_enrollment_id", None)
                        == getattr(observer, "observer_enrollment_id", None)]
            if len(matching) != 1:
                raise AuthorityDenied("source.target", "observer has no unique protected pending-pair role")
            role = matching[0].delivery_role
            selected = producer if role == "producer" else gateway
            unselected = gateway if role == "producer" else producer
            if selected is None or unselected is None or selected is unselected:
                raise AuthorityDenied("source.target", "pending pair peer selection is ambiguous")
            selected_identity = _validate_pending_peer(selected, custody=None)
            if (getattr(selected, "profile_id", None) != getattr(observer, "profile_id", None)
                    and role == "producer"):
                raise AuthorityDenied("source.target", "producer peer differs from the protected observer profile")
            try:
                os.close(unselected.pidfd)
            except OSError:
                pass
            # Transfer the selected duplicate to RootNativeLoaderObservationStore.
            return _SelectedNativeTarget(
                selected.pid, selected.pidfd, selected.uid,
                selected.profile_id, selected.generation, selected_identity,
            )
        except BaseException:
            _close_pending_pair_duplicates(pair)
            raise

    return select


def active_native_catalog_resolver(bindings: Any, *,
                                   service_generation_digest: str
                                   ) -> Callable[[Any], NativeLoaderSelection]:
    """Resolve the unique loader/action role set from active protected bindings.

    Package choice comes from the manager-owned process generation plus the
    observer's protected native-package generation. Process roles, adapters,
    registrations, and effect actions remain distinct catalog records.
    """
    from .source_observers import SourceObserverEnrollment

    _digest(service_generation_digest, "active service generation digest")
    catalog_resolver = getattr(bindings, "resolve_native_package", None)
    candidates = getattr(bindings, "source_observer_enrollments", None)
    if not callable(catalog_resolver) or not isinstance(candidates, Mapping):
        raise ValueError("native loader selection requires active protected runtime bindings")

    def resolve(owned_process_handle: Any) -> NativeLoaderSelection:
        profile = getattr(owned_process_handle, "profile", None)
        profile_id = getattr(profile, "profile_id", None)
        generation = getattr(profile, "generation", None)
        process_id = getattr(owned_process_handle, "process_id", None)
        if (not isinstance(profile_id, str) or not profile_id
                or not isinstance(generation, str) or not generation
                or not isinstance(process_id, str) or not process_id):
            raise AuthorityDenied("native.package", "manager-owned process handle lacks its active profile identity")
        observers = [item for item in candidates.values()
                     if isinstance(item, SourceObserverEnrollment)
                     and item.profile_id == profile_id and item.generation == generation]
        package_ids = {(item.package_id, item.native_package_generation)
                       for item in observers if item.native_package_generation}
        if len(package_ids) != 1 or any(not item.native_package_generation for item in observers):
            raise AuthorityDenied("native.package", "process generation has no unique native package generation")
        package_id, package_generation = next(iter(package_ids))
        package = catalog_resolver(package_id, package_generation)
        role_records = getattr(package, "process_role_records", None)
        action_records = getattr(package, "action_records", None)
        registration_records = getattr(package, "registration_records", None)
        if (getattr(package, "package_id", None) != package_id
                or getattr(package, "profile_id", None) != profile_id
                or getattr(package, "generation", None) != package_generation
                or getattr(package, "profile_generation", None) != generation
                or not isinstance(role_records, Mapping)
                or not isinstance(action_records, Mapping)
                or not isinstance(registration_records, Mapping)):
            raise AuthorityDenied("native.package", "selected package differs from active protected role joins")
        observer_by_id = {item.observer_enrollment_id: item for item in observers}
        role_actions: set[tuple[str, str, str, str]] = set()
        selected_roles: dict[str, NativeProcessRoleSelection] = {}
        action_ids: set[str] = set()
        registration_ids: set[str] = set()
        for observer in observers:
            role = role_records.get(observer.role_id)
            if (role is None or role.package_id != package_id
                    or role.native_package_generation != package_generation
                    or role.profile_id != profile_id or role.profile_generation != generation
                    or observer.observer_enrollment_id not in role.observer_enrollment_ids
                    or observer.role_artifact_id != role.role_artifact_id
                    or observer.role_sha256 != role.role_sha256
                    or observer.role_source_receipt_handle != role.role_source_receipt_handle
                    or observer.role_module_name != role.module_name
                    or observer.role_closure_member_path != role.closure_member_path
                    or observer.role_source_revision != role.role_source_revision
                    or observer.role_source_tree_sha256 != role.role_source_tree_sha256):
                raise AuthorityDenied("native.package", "source observer does not match its protected process role")
            previous_role = selected_roles.get(role.role_id)
            selected_role = NativeProcessRoleSelection(
                role_id=role.role_id, role_artifact_id=role.role_artifact_id,
                role_sha256=role.role_sha256, profile_generation=role.profile_generation,
                native_package_generation=role.native_package_generation,
                role_source_receipt_handle=role.role_source_receipt_handle,
                module_name=role.module_name, closure_member_path=role.closure_member_path,
                role_source_revision=role.role_source_revision,
                role_source_tree_sha256=role.role_source_tree_sha256,
                registration_ids=tuple(sorted(role.registration_ids)),
                action_binding_ids=tuple(sorted(role.action_binding_ids)),
            )
            if previous_role is not None and previous_role != selected_role:
                raise AuthorityDenied("native.package", "process role assignment is ambiguous")
            selected_roles[role.role_id] = selected_role
            matching_actions = [item for item in action_records.values()
                                if item.action_binding_id in role.action_binding_ids
                                and item.action_id == observer.source_action_id
                                and observer.observer_enrollment_id in item.observer_enrollment_ids
                                and (observer.source_action_binding_id is None
                                     or item.action_binding_id == observer.source_action_binding_id)]
            if len(matching_actions) != 1:
                raise AuthorityDenied("native.package", "source action is absent or ambiguous within its process role")
            action = matching_actions[0]
            if (action.generation != package_generation
                    or action.target_id != observer.target_id or action.recipient != observer.recipient
                    or any(registration_id not in registration_records
                           for registration_id in role.registration_ids)):
                raise AuthorityDenied("native.package", "source role action or registration join is stale")
            registrations_for_action = tuple(sorted(
                registration_id for registration_id in role.registration_ids
                if registration_id in registration_records
                and any(getattr(binding, "action_binding_id", None) == action.action_binding_id
                        for binding in getattr(registration_records[registration_id], "action_bindings", ()))
            ))
            expected_source_registrations = getattr(observer, "source_registration_ids", ())
            if (not isinstance(expected_source_registrations, tuple)
                    or not expected_source_registrations
                    or tuple(sorted(set(expected_source_registrations))) != expected_source_registrations
                    or registrations_for_action != expected_source_registrations):
                raise AuthorityDenied("native.package", "selected source registration/action foreign keys differ")
            registration_ids.update(role.registration_ids)
            action_ids.add(action.action_id)
            role_actions.add((role.role_id, role.role_artifact_id, role.role_sha256, action.action_id))
        if not action_ids or not role_actions or not selected_roles:
            raise AuthorityDenied("native.package", "selected package has no exact process-role/source-action join")
        return NativeLoaderSelection(
            process_id=process_id,
            package_id=package.package_id,
            profile_id=profile_id,
            generation=generation,
            package_generation=package_generation,
            compiled_closure_sha256=package.compiled_closure_sha256,
            entrypoint_sha256=package.entrypoint_sha256,
            resolver_sha256=package.resolver_sha256,
            service_generation_digest=service_generation_digest,
            loader_role_artifact_id=package.entrypoint_artifact_id,
            loader_role_sha256=package.entrypoint_sha256,
            registered_action_ids=tuple(sorted(action_ids)),
            registered_registration_ids=tuple(sorted(registration_ids)),
            observer_role_action_bindings=tuple(sorted(role_actions)),
            process_roles=tuple(sorted(selected_roles.values(), key=lambda item: item.role_id)),
        )

    return resolve


@dataclass(frozen=True, slots=True)
class _SelectedNativeTarget:
    pid: int
    pidfd: int
    uid: int
    profile_id: str
    generation: str
    identity: Any


def _validate_pending_native_pair(pair: Any, parent_context: HostContext,
                                  observer: Any, now: float) -> None:
    if (pair is None or type(getattr(pair, "schema", None)) is not int
            or pair.schema != 1
            or not all(isinstance(getattr(pair, name, None), str) and getattr(pair, name)
                       for name in ("pair_id", "bridge_enrollment_id", "native_request_handle",
                                    "parent_grant_id", "intent_id", "trace_id"))
            or not all(_valid_digest(getattr(pair, name, None))
                       for name in ("parent_context_sha256", "parent_closure_digest",
                                    "service_generation_digest"))
            or getattr(pair, "parent_context_sha256", None)
            != canonical_digest(parent_context.to_wire())
            or getattr(pair, "parent_grant_id", None) != parent_context.grant_id
            or getattr(pair, "intent_id", None) != parent_context.intent_id
            or getattr(pair, "trace_id", None) != parent_context.trace_id
            or getattr(pair, "parent_closure_digest", None) != parent_context.lineage_hash
            or type(getattr(pair, "expires_monotonic", None)) not in (int, float)
            or not math.isfinite(pair.expires_monotonic) or now >= pair.expires_monotonic):
        raise AuthorityDenied("source.target", "root pending HI11 pair is stale or mismatched")
    bindings = getattr(pair, "observer_delivery_bindings", None)
    if (not isinstance(bindings, tuple)
            or any(getattr(item, "delivery_role", None) not in ("producer", "gateway")
                   or not isinstance(getattr(item, "observer_enrollment_id", None), str)
                   or not getattr(item, "observer_enrollment_id", None) for item in bindings)
            or len({item.observer_enrollment_id for item in bindings}) != len(bindings)
            or not any(item.observer_enrollment_id == observer.observer_enrollment_id
                       for item in bindings)):
        raise AuthorityDenied("source.target", "pending pair lacks the protected observer delivery mapping")


def _validate_pending_peer(peer: Any, custody: Any) -> Any:
    if (getattr(peer, "role", None) not in ("producer", "gateway")
            or not isinstance(getattr(peer, "principal_id", None), str)
            or not isinstance(getattr(peer, "profile_id", None), str)
            or not isinstance(getattr(peer, "generation", None), str)
            or type(getattr(peer, "pid", None)) is not int or peer.pid <= 0
            or type(getattr(peer, "pidfd", None)) is not int or peer.pidfd < 0
            or type(getattr(peer, "uid", None)) is not int or peer.uid < 0
            or not _identifier_value(getattr(peer, "role_artifact_id", None))
            or not _valid_digest(getattr(peer, "role_artifact_sha256", None))):
        raise AuthorityDenied("source.target", "pending HI11 peer fields are malformed")
    if (RootNativeLoaderObservationStore._pidfd_target(peer.pidfd) != peer.pid
            or RootNativeLoaderObservationStore._pidfd_exited(peer.pidfd)):
        raise AuthorityDenied("source.target", "pending HI11 peer PIDFD is stale")
    identity = getattr(peer, "identity", None)
    if (identity is None or identity.profile_id != peer.profile_id
            or identity.generation != peer.generation or identity.kernel_uid != peer.uid
            or not _valid_digest(getattr(identity, "executable_sha256", None))):
        raise AuthorityDenied("source.target", "pending HI11 peer does not match its root kernel identity")
    if custody is not None:
        current = custody.resolve_live_peer(peer.pid, peer.pidfd,
                                            profile_id=peer.profile_id,
                                            generation=peer.generation)
        if current is None or current != identity:
            raise AuthorityDenied("source.target", "pending HI11 peer identity changed")
    return identity


def _identifier_value(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 256
            and not any(ord(char) < 0x20 for char in value))


def _close_pending_pair_duplicates(pair: Any) -> None:
    for name in ("producer", "gateway"):
        peer = getattr(pair, name, None)
        pidfd = getattr(peer, "pidfd", None)
        if type(pidfd) is int and pidfd >= 0:
            try:
                os.close(pidfd)
            except OSError:
                pass


@dataclass(frozen=True, slots=True)
class _ProgressRecord:
    launch_nonce: str
    sequence: int
    phase: str
    package_id: str
    generation: str
    package_generation: str
    entrypoint_sha256: str
    resolver_sha256: str
    registered_registration_ids: tuple[str, ...]
    loaded_process_roles: tuple[LoadedProcessRoleObservation, ...]


@dataclass(slots=True)
class _LaunchObservation:
    handle: str
    owned_process_handle: Any
    selection: NativeLoaderSelection
    listener_socket: socket.socket | None
    parent_socket: socket.socket | None
    socket_path: Path
    socket_directory: Path
    child_pid: int
    child_pidfd: int
    child_uid: int
    child_gid: int
    child_start_ticks: int
    child_cgroup: str
    child_namespace: str
    launch_nonce: str
    deadline: float
    ready_event_id: str | None = None
    progress: tuple[_ProgressRecord, ...] = ()
    proofs: dict[str, LoadedPackageClosureProof] | None = None
    revoked: bool = False


@dataclass(slots=True)
class NativeLoaderChannel:
    """One private listener passed only as a named systemd OpenFile property."""

    listener: socket.socket
    socket_path: Path
    socket_directory: Path
    launch_nonce: str
    _transferred: bool = False

    @property
    def systemd_open_file_property(self) -> str:
        """Value for the fixed root-generated unit property, never worker input."""
        if self._transferred or self.listener.fileno() < 0:
            raise AuthorityDenied("native.loader", "loader channel is no longer available")
        return f"{self.socket_path}:hermes-loader-progress"

    def close(self) -> None:
        if self._transferred:
            return
        self._transferred = True
        _close_loader_path(self.listener, self.socket_path, self.socket_directory)


def create_native_loader_channel(runtime_directory: Path) -> NativeLoaderChannel:
    """Create the root-private listener used by systemd's named OpenFile FD.

    systemd v253+ connects this AF_UNIX path and passes the connected descriptor
    under the fixed ``hermes-loader-progress`` name. The worker never receives
    the path or nonce in argv/environment; root challenges it after accept.
    """
    if not isinstance(runtime_directory, Path):
        raise AuthorityDenied("native.loader", "root loader runtime directory is invalid")
    try:
        directory_info = runtime_directory.lstat()
    except OSError:
        raise AuthorityDenied("native.loader", "root loader runtime directory is unavailable") from None
    if (not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.geteuid()
            or stat.S_IMODE(directory_info.st_mode) != 0o700):
        raise AuthorityDenied("native.loader", "root loader runtime directory is not private and owned")
    launch_directory = runtime_directory / secrets.token_hex(16)
    try:
        launch_directory.mkdir(mode=0o700)
        directory_info = launch_directory.lstat()
        if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != os.geteuid()
                or stat.S_IMODE(directory_info.st_mode) != 0o700):
            raise OSError("private loader directory ownership changed")
        socket_path = launch_directory / "progress.sock"
    except OSError:
        raise AuthorityDenied("native.loader", "root could not create a private loader directory") from None
    flags = getattr(socket, "SOCK_CLOEXEC", 0)
    listener: socket.socket | None = None
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | flags)
        if not hasattr(socket, "SO_PASSCRED"):
            raise OSError("per-message credentials are unavailable")
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600, follow_symlinks=False)
        listener.listen(1)
        listener.set_inheritable(False)
    except OSError as exc:
        try:
            if listener is not None:
                listener.close()
        except OSError:
            pass
        _close_loader_path(None, socket_path, launch_directory)
        raise AuthorityDenied("native.loader", "private loader activation listener is unavailable") from exc
    return NativeLoaderChannel(listener, socket_path, launch_directory, secrets.token_urlsafe(32))


def encode_loader_progress(*, launch_nonce: str, sequence: int, phase: str,
                           package_id: str, generation: str, package_generation: str,
                           entrypoint_sha256: str, resolver_sha256: str,
                           registered_registration_ids: tuple[str, ...] | list[str],
                           loaded_process_roles: tuple[LoadedProcessRoleObservation, ...] | list[LoadedProcessRoleObservation] = ()) -> bytes:
    """Encode one canonical progress frame for the selected loader hook."""
    record = {
        "schema": 2, "launch_nonce": launch_nonce, "sequence": sequence,
        "phase": phase, "package_id": package_id, "generation": generation,
        "package_generation": package_generation,
        "entrypoint_sha256": entrypoint_sha256,
        "resolver_sha256": resolver_sha256,
        "registered_registration_ids": list(registered_registration_ids),
        "loaded_process_roles": [
            {"role_id": item.role_id, "module_name": item.module_name,
             "closure_member_path": item.closure_member_path,
             "module_file_sha256": item.module_file_sha256,
             "module_file_device": item.module_file_device,
             "module_file_inode": item.module_file_inode,
             "module_file_size_bytes": item.module_file_size_bytes}
            for item in loaded_process_roles
        ],
    }
    payload = _canonical_json(record)
    if len(payload) > MAX_PROGRESS_BYTES:
        raise ValueError("loader progress frame exceeds its bound")
    return _FRAME_HEADER.pack(len(payload)) + payload


def attach_root_source_observers(*, service: Any,
                                 observer_enrollments: Mapping[str, Any],
                                 process_resolver: Callable[..., Any],
                                 package_resolver: Callable[[str, str], Any],
                                 loader_observations: "RootNativeLoaderObservationStore") -> Any:
    """Build and attach the one root source registry for the active service.

    The inputs are already-derived objects from the active protected runtime
    composition. Missing loader or recipient resolvers are rejected during
    store construction; this function does not turn metadata into readiness.
    """
    from .source_observers import SourceObserverEnrollment, SourceObserverRegistry

    if (not isinstance(observer_enrollments, Mapping) or not observer_enrollments
            or not callable(process_resolver) or not callable(package_resolver)
            or not isinstance(loader_observations, RootNativeLoaderObservationStore)
            or getattr(service, "source_observer_registry", None) is not None
            or getattr(service, "native_loader_observation_store", None) is not None
            or not hasattr(service, "__dict__")
            or not callable(getattr(service, "attach_source_observer_registry", None))):
        raise AuthorityDenied("source.composition", "active root source-observer composition is incomplete")
    observers = dict(observer_enrollments)
    if any(not isinstance(key, str) or not isinstance(value, SourceObserverEnrollment)
           or key != value.observer_enrollment_id for key, value in observers.items()):
        raise AuthorityDenied("source.composition", "source observer metadata is not a typed protected join")
    registry = SourceObserverRegistry(
        service=service,
        observers=observers,
        process_resolver=process_resolver,
        package_resolver=package_resolver,
        target_peer_resolver=loader_observations.resolve_source_target_peer,
        loaded_package_proof_resolver=loader_observations.source_observer_loaded_package_resolver,
    )
    try:
        service.native_loader_observation_store = loader_observations
        service.attach_source_observer_registry(registry)
    except BaseException:
        try:
            del service.native_loader_observation_store
        except AttributeError:
            pass
        registry.close()
        loader_observations.close()
        raise
    return registry


class RootNativeLoaderObservationStore:
    """Root-only bounded loader event store and source custody proof resolver.

    ``custody_resolver`` is the concrete process manager. It must expose
    ``is_owned_active_process_handle``, ``resolve_live_peer`` and
    ``resolve_native_package_for_peer``. The active
    catalog callback takes the manager-owned process handle and returns one
    ``NativeLoaderSelection``. ``source_target_selector`` is the root's exact
    current HI11 selector; it accepts only the observer and signed parent
    context, never a worker PID/profile selector.
    """

    def __init__(self, custody_resolver: Any,
                 active_catalog_resolver: Callable[[Any], NativeLoaderSelection],
                 clock: Callable[[], float] = time.monotonic,
                 source_target_selector: Callable[[Any, HostContext], Any] | None = None):
        if (not callable(getattr(custody_resolver, "is_owned_active_process_handle", None))
                or not callable(getattr(custody_resolver, "resolve_live_peer", None))
                or not callable(getattr(custody_resolver, "resolve_native_package_for_peer", None))
                or not callable(active_catalog_resolver) or not callable(clock)
                or not callable(source_target_selector)):
            raise ValueError("native custody requires concrete root process, package, and target resolvers")
        self.custody_resolver = custody_resolver
        self.active_catalog_resolver = active_catalog_resolver
        self.source_target_selector = source_target_selector
        self.clock = clock
        self._lock = threading.RLock()
        self._launches: dict[str, _LaunchObservation] = {}
        self._by_process: dict[str, str] = {}
        self._closed = False

    def register_launch(self, owned_process_handle: Any, parent_socket: NativeLoaderChannel,
                        expected_loader_role_artifact_id: str,
                        expected_loader_role_sha256: str, launch_nonce: str,
                        deadline_monotonic: float) -> str:
        """Register one current manager-owned launch before reading its frames."""
        if (not isinstance(parent_socket, NativeLoaderChannel)
                or parent_socket._transferred
                or parent_socket.listener.family != socket.AF_UNIX
                or not isinstance(launch_nonce, str)
                or not _nonce(launch_nonce)
                or launch_nonce != parent_socket.launch_nonce
                or type(deadline_monotonic) not in (float, int)
                or not math.isfinite(deadline_monotonic)):
            raise AuthorityDenied("native.loader", "loader launch registration is malformed")
        now = self.clock()
        if not now < deadline_monotonic <= now + MAX_LAUNCH_LEASE_SECONDS:
            raise AuthorityDenied("native.loader", "loader launch deadline is outside its finite lease")
        if not self.custody_resolver.is_owned_active_process_handle(owned_process_handle):
            raise AuthorityDenied("native.loader", "loader process handle is not current root manager state")
        selection = self.active_catalog_resolver(owned_process_handle)
        if (not isinstance(selection, NativeLoaderSelection)
                or selection.loader_role_artifact_id != expected_loader_role_artifact_id
                or selection.loader_role_sha256 != expected_loader_role_sha256):
            raise AuthorityDenied("native.loader", "loader role differs from the protected active package")
        process_id = getattr(owned_process_handle, "process_id", None)
        pid = getattr(owned_process_handle, "pid", None)
        pidfd = getattr(owned_process_handle, "child_pidfd", None)
        start_ticks = getattr(owned_process_handle, "start_ticks", None)
        cgroup = getattr(owned_process_handle, "cgroup", None)
        namespace = getattr(owned_process_handle, "kernel_namespace_id", None)
        profile = getattr(owned_process_handle, "profile", None)
        uid = getattr(profile, "owner_uid", None)
        gid = getattr(profile, "owner_gid", None)
        expiry = getattr(owned_process_handle, "expires", None)
        if (process_id != selection.process_id or type(pid) is not int or pid <= 0
                or type(pidfd) is not int or pidfd < 0
                or not isinstance(cgroup, str) or not cgroup
                or not isinstance(namespace, str) or not namespace
                or type(uid) is not int or uid <= 0 or type(gid) is not int or gid <= 0
                or type(expiry) not in (float, int) or deadline_monotonic > expiry
                or self._pidfd_target(pidfd) != pid or self._pidfd_exited(pidfd)):
            raise AuthorityDenied("native.loader", "launch handle is not a current manager-owned child")
        identity = self.custody_resolver.resolve_live_peer(
            pid, pidfd, profile_id=selection.profile_id, generation=selection.generation,
        )
        if (identity is None or identity.kernel_uid != uid
                or identity.start_ticks != start_ticks
                or identity.cgroup_identity != cgroup
                or identity.namespace_identity != namespace
                or identity.executable_sha256 != getattr(profile, "artifact_sha256", None)):
            raise AuthorityDenied("native.loader", "launch identity is not current in root custody")
        try:
            retained_listener = socket.socket(fileno=os.dup(parent_socket.listener.fileno()))
            retained_listener.set_inheritable(False)
            retained_pidfd = os.dup(pidfd)
        except OSError:
            try:
                retained_listener.close()
            except (OSError, UnboundLocalError):
                pass
            raise AuthorityDenied("native.loader", "root could not retain the private listener and PIDFD") from None
        if not hasattr(socket, "SO_PASSCRED"):
            retained_listener.close()
            os.close(retained_pidfd)
            raise AuthorityDenied("native.loader", "kernel per-message loader credentials are unavailable")
        parent_socket._transferred = True
        parent_socket.listener.close()
        handle = secrets.token_urlsafe(32)
        entry = _LaunchObservation(
            handle, owned_process_handle, selection, retained_listener, None,
            parent_socket.socket_path, parent_socket.socket_directory, pid,
            retained_pidfd, uid, gid, start_ticks, cgroup, namespace, launch_nonce,
            float(deadline_monotonic), proofs={},
        )
        with self._lock:
            if self._closed or process_id in self._by_process:
                self._close_entry(entry)
                _close_loader_path(None, entry.socket_path, entry.socket_directory)
                raise AuthorityDenied("native.loader", "loader launch is retired or duplicated")
            self._launches[handle] = entry
            self._by_process[process_id] = handle
        return handle

    def receive_loader_progress(self, launch_observation_handle: str,
                                cancelled: Callable[[], bool]) -> str:
        """Read, authenticate and consume exactly the three selected loader frames."""
        if not callable(cancelled):
            raise AuthorityDenied("native.loader", "loader cancellation callback is unavailable")
        with self._lock:
            entry = self._launches.get(launch_observation_handle)
        if entry is None or entry.revoked or entry.ready_event_id is not None:
            raise AuthorityDenied("native.loader", "loader observation is unknown, stale, or already consumed")
        accepted: list[_ProgressRecord] = []
        try:
            self._accept_loader_connection(entry, cancelled)
            for sequence, phase in enumerate(_PHASES):
                record = self._read_progress(entry, cancelled)
                self._assert_current_launch(entry)
                self._validate_progress(entry, record, sequence, phase,
                                        accepted[-1] if accepted else None)
                accepted.append(record)
            # The protocol closes the child endpoint after READY. Reject a fourth
            # frame or a channel kept open beyond the original deadline.
            if self._read_after_ready(entry, cancelled):
                raise AuthorityDenied("native.loader", "loader sent data after its ready frame")
            if cancelled():
                raise AuthorityDenied("native.cancelled", "loader observation was cancelled")
            ready_event_id = secrets.token_urlsafe(32)
            with self._lock:
                if entry.revoked or self._closed:
                    raise AuthorityDenied("native.loader", "loader observation was revoked")
                entry.progress = tuple(accepted)
                entry.ready_event_id = ready_event_id
                if entry.parent_socket is not None:
                    entry.parent_socket.close()
                entry.parent_socket = _closed_socket()
            return ready_event_id
        except BaseException:
            self.revoke_launch(launch_observation_handle)
            raise

    def resolve_loaded_package_closure(self, live_peer: LivePeerProcess,
                                       observer: Any) -> LoadedPackageClosureProof:
        """Return one stable proof while rechecking current peer and mount facts."""
        if (not isinstance(live_peer, LivePeerProcess)
                or type(live_peer.pid) is not int or live_peer.pid <= 0
                or type(live_peer.pidfd) is not int or live_peer.pidfd < 0
                or live_peer.identity is None):
            raise AuthorityDenied("native.peer", "source producer peer binding is invalid")
        mount_proof = self.custody_resolver.resolve_native_package_for_peer(
            live_peer.pid, live_peer.pidfd)
        if mount_proof is None:
            self._revoke_matching_peer(live_peer.pid)
            raise AuthorityDenied("native.mount", "root did not observe a current immutable package mount")
        process_id = getattr(mount_proof, "process_id", None)
        with self._lock:
            handle = self._by_process.get(process_id)
            entry = self._launches.get(handle) if handle else None
        if (entry is None or entry.revoked or entry.ready_event_id is None
                or not entry.progress or entry.selection.process_id != process_id):
            raise AuthorityDenied("native.loader", "selected root loader has no complete ready observation")
        self._assert_current_launch(entry)
        identity = self.custody_resolver.resolve_live_peer(
            live_peer.pid, live_peer.pidfd,
            profile_id=entry.selection.profile_id,
            generation=entry.selection.generation,
        )
        if identity is None or identity != live_peer.identity:
            self._revoke_matching_peer(live_peer.pid)
            raise AuthorityDenied("native.peer", "source producer PIDFD identity changed")
        selection = self.active_catalog_resolver(entry.owned_process_handle)
        if selection != entry.selection:
            self.revoke_launch(entry.handle)
            raise AuthorityDenied("native.package", "active native package selection changed after loader readiness")
        mount = getattr(mount_proof, "mount", None)
        if (getattr(mount_proof, "profile_id", None) != selection.profile_id
                or getattr(mount_proof, "generation", None) != selection.generation
                or getattr(mount_proof, "kernel_uid", None) != identity.kernel_uid
                or getattr(mount_proof, "pid_start_ticks", None) != identity.start_ticks
                or getattr(mount_proof, "cgroup_identity", None) != identity.cgroup_identity
                or getattr(mount_proof, "namespace_identity", None) != identity.namespace_identity
                or getattr(mount_proof, "executable_sha256", None) != identity.executable_sha256
                or getattr(mount, "package_id", None) != selection.package_id
                or getattr(mount, "compiled_closure_sha256", None) != selection.compiled_closure_sha256
                or getattr(mount, "entrypoint_sha256", None) != selection.entrypoint_sha256
                or getattr(mount, "resolver_sha256", None) != selection.resolver_sha256
                or not getattr(mount, "private_propagation", False)):
            self.revoke_launch(entry.handle)
            raise AuthorityDenied("native.mount", "current mount or process identity differs from loaded package selection")
        observer_role_binding = (
            getattr(observer, "role_id", None),
            getattr(observer, "role_artifact_id", None),
            getattr(observer, "role_sha256", None),
            getattr(observer, "source_action_id", None),
        )
        role = next((item for item in selection.process_roles
                     if item.role_id == getattr(observer, "role_id", None)), None)
        observed_role = (None if not entry.progress else next(
            (item for item in entry.progress[0].loaded_process_roles
             if item.role_id == getattr(observer, "role_id", None)), None))
        if (getattr(observer, "profile_id", None) != selection.profile_id
                or getattr(observer, "generation", None) != selection.generation
                or getattr(observer, "package_id", None) != selection.package_id
                or getattr(observer, "native_package_generation", None) != selection.package_generation
                or role is None
                or getattr(observer, "role_source_receipt_handle", None) != role.role_source_receipt_handle
                or getattr(observer, "role_module_name", None) != role.module_name
                or getattr(observer, "role_closure_member_path", None) != role.closure_member_path
                or getattr(observer, "role_source_revision", None) != role.role_source_revision
                or getattr(observer, "role_source_tree_sha256", None) != role.role_source_tree_sha256
                or observer_role_binding not in selection.observer_role_action_bindings
                or getattr(observer, "source_action_id", None) not in selection.registered_action_ids
                or observed_role is None
                or not set(role.registration_ids).issubset(entry.progress[-1].registered_registration_ids)):
            raise AuthorityDenied("native.observer", "protected observer role or action is outside loaded package closure")
        verified_module = _verify_mounted_role_module(
            live_peer.pid, mount.mount_path, role, observed_role)
        if verified_module is None:
            self.revoke_launch(entry.handle)
            raise AuthorityDenied("native.loader", "loaded role module origin differs from the mounted package bytes")
        module_device, module_inode, module_digest, module_size = verified_module
        # Recheck both process lease and exact mount after opening the module
        # origin, so a PID reuse or mount replacement cannot race proof minting.
        self._assert_current_launch(entry)
        current_mount = self.custody_resolver.resolve_native_package_for_peer(
            live_peer.pid, live_peer.pidfd)
        if current_mount is None or current_mount != mount_proof:
            self.revoke_launch(entry.handle)
            raise AuthorityDenied("native.mount", "package mount changed while role module identity was verified")
        now = self.clock()
        with self._lock:
            if (self._closed or entry.revoked
                    or self._by_process.get(entry.selection.process_id) != entry.handle
                    or self.clock() >= entry.deadline):
                raise AuthorityDenied("native.loader", "loader proof launch was revoked before admission")
            previous = (entry.proofs or {}).get(observer.observer_enrollment_id)
            mount_ns_inode = _mount_namespace_inode(identity)
            flags = tuple(sorted(set(getattr(mount, "verified_mount_options", ()))))
            if not {"ro", "nosuid", "nodev"}.issubset(flags) or "rw" in flags:
                raise AuthorityDenied("native.mount", "native package mount flags are incomplete")
            mount_target_digest = canonical_digest({
                "mount_path": mount.mount_path,
                "service_mount_id": mount.service_mount_id,
                "manifest_sha256": mount.manifest_sha256,
                "source_device": mount.mount_source_device,
                "source_inode": mount.mount_source_inode,
                "flags": flags,
                "private_propagation": mount.private_propagation,
            })
            if previous is not None:
                if now >= previous.expires_monotonic:
                    self.revoke_launch(entry.handle)
                    raise AuthorityDenied("native.expired", "loaded package proof lease expired")
                if (previous.target_peer_identity != identity
                        or previous.mount_namespace_inode != mount_ns_inode
                        or previous.mount_id != str(mount.service_mount_id)
                        or previous.mount_target_digest != mount_target_digest
                        or previous.mount_flags != flags
                        or previous.source_root_device != mount.mount_source_device
                        or previous.source_root_inode != mount.mount_source_inode
                        or previous.loader_ready_event_id != entry.ready_event_id
                        or previous.observed_registration_ids != entry.progress[-1].registered_registration_ids
                        or previous.role_module_device != module_device
                        or previous.role_module_inode != module_inode
                        or previous.role_module_sha256 != module_digest
                        or previous.role_module_size_bytes != module_size):
                    self.revoke_launch(entry.handle)
                    raise AuthorityDenied("native.mount", "mounted or loaded package identity changed during its lease")
                return previous
            issued = now
            expires = min(entry.deadline, float(getattr(entry.owned_process_handle, "expires")),
                          now + float(observer.lease_seconds), now + MAX_LAUNCH_LEASE_SECONDS)
            if not issued < expires:
                raise AuthorityDenied("native.expired", "loaded package proof has no remaining lease")
            proof = LoadedPackageClosureProof(
                schema=1,
                proof_id=secrets.token_urlsafe(32),
                package_id=selection.package_id,
                profile_id=selection.profile_id,
                generation=selection.generation,
                compiled_closure_sha256=selection.compiled_closure_sha256,
                entrypoint_sha256=selection.entrypoint_sha256,
                resolver_sha256=selection.resolver_sha256,
                mount_namespace_inode=mount_ns_inode,
                mount_id=str(mount.service_mount_id),
                mount_target_digest=mount_target_digest,
                mount_flags=flags,
                source_root_device=mount.mount_source_device,
                source_root_inode=mount.mount_source_inode,
                target_peer_identity=identity,
                loader_role_artifact_id=observer_role_binding[0],
                loader_role_sha256=observer_role_binding[1],
                loader_ready_event_id=entry.ready_event_id,
                # v134 authenticates registration IDs. Action binding remains
                # a separate selected catalog join; an old action-named field
                # must never be populated by relabeling registration claims.
                observed_entrypoint_action_ids=(),
                issued_monotonic=issued,
                expires_monotonic=expires,
                service_generation_digest=selection.service_generation_digest,
                role_id=role.role_id,
                role_source_receipt_handle=role.role_source_receipt_handle,
                role_module_name=role.module_name,
                role_closure_member_path=role.closure_member_path,
                role_source_revision=role.role_source_revision,
                role_source_tree_sha256=role.role_source_tree_sha256,
                role_module_device=module_device,
                role_module_inode=module_inode,
                role_module_sha256=module_digest,
                role_module_size_bytes=module_size,
                observed_registration_ids=entry.progress[-1].registered_registration_ids,
            )
            if entry.proofs is None:
                entry.proofs = {}
            entry.proofs[observer.observer_enrollment_id] = proof
            return proof

    def source_observer_loaded_package_resolver(self, identity: Any, observer: Any,
                                                *, peer_pid: int, peer_pidfd: int) -> LoadedPackageClosureProof:
        """Adapter for SourceObserverRegistry's root-private resolver callback."""
        return self.resolve_loaded_package_closure(
            LivePeerProcess(peer_pid, peer_pidfd, identity), observer)

    def resolve_source_target_peer(self, observer: Any,
                                   parent_context: HostContext) -> ResolvedTargetPeer:
        """Resolve only the root-selected same-producer or active HI11 recipient."""
        if not isinstance(parent_context, HostContext):
            raise AuthorityDenied("source.target", "root parent context is unavailable")
        selected = self.source_target_selector(observer, parent_context)
        pid = getattr(selected, "pid", None)
        borrowed_pidfd = getattr(selected, "pidfd", None)
        uid = getattr(selected, "uid", None)
        profile_id = getattr(selected, "profile_id", None)
        generation = getattr(selected, "generation", None)
        expected_identity = getattr(selected, "identity", None)
        if (type(borrowed_pidfd) is not int or borrowed_pidfd < 0):
            raise AuthorityDenied("source.target", "root-selected recipient PIDFD is invalid")
        try:
            if (type(pid) is not int or pid <= 0 or type(uid) is not int or uid <= 0
                    or not isinstance(profile_id, str) or not profile_id
                    or not isinstance(generation, str) or not generation
                    or expected_identity is None
                    or self._pidfd_target(borrowed_pidfd) != pid
                    or self._pidfd_exited(borrowed_pidfd)):
                raise AuthorityDenied("source.target", "root-selected recipient PIDFD is invalid")
            current = self.custody_resolver.resolve_live_peer(
                pid, borrowed_pidfd, profile_id=profile_id, generation=generation)
            if current is None or current != expected_identity or current.kernel_uid != uid:
                raise AuthorityDenied("source.target", "root-selected recipient identity is stale")
            try:
                owned_pidfd = os.dup(borrowed_pidfd)
            except OSError:
                raise AuthorityDenied("source.target", "recipient PIDFD could not be retained") from None
            if self._pidfd_target(owned_pidfd) != pid or self._pidfd_exited(owned_pidfd):
                os.close(owned_pidfd)
                raise AuthorityDenied("source.target", "recipient changed while its PIDFD was retained")
            return ResolvedTargetPeer(pid, owned_pidfd, uid, profile_id, generation, current)
        finally:
            # Root selector returns a one-use duplicate from its same-producer
            # or HI11 pair record. The SourceObserverRegistry will own this new
            # duplicate after it retains its own copy.
            try:
                os.close(borrowed_pidfd)
            except OSError:
                pass

    def revoke_launch(self, launch_observation_handle: str) -> None:
        with self._lock:
            entry = self._launches.pop(launch_observation_handle, None)
            if entry is None:
                return
            entry.revoked = True
            self._by_process.pop(entry.selection.process_id, None)
        self._close_entry(entry)

    def revoke_process(self, process_id: str, generation: str | None = None) -> None:
        with self._lock:
            handle = self._by_process.get(process_id)
            entry = self._launches.get(handle) if handle is not None else None
            if (entry is None or (generation is not None
                                  and generation != entry.selection.generation)):
                return
        self.revoke_launch(handle)

    def _revoke_matching_peer(self, peer_pid: int) -> None:
        with self._lock:
            handles = tuple(entry.handle for entry in self._launches.values()
                            if entry.child_pid == peer_pid)
        for handle in handles:
            self.revoke_launch(handle)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            handles = tuple(self._launches)
        for handle in handles:
            self.revoke_launch(handle)

    def _read_progress(self, entry: _LaunchObservation,
                       cancelled: Callable[[], bool]) -> _ProgressRecord:
        header, credentials = self._recv_exact(entry, _FRAME_HEADER.size, cancelled)
        (length,) = _FRAME_HEADER.unpack(header)
        if not 1 <= length <= MAX_PROGRESS_BYTES:
            raise AuthorityDenied("native.loader", "loader progress frame length is outside its bound")
        payload, payload_credentials = self._recv_exact(entry, length, cancelled)
        if payload_credentials != credentials:
            raise AuthorityDenied("native.loader", "loader frame segments changed sender identity")
        record = _parse_progress(payload)
        if credentials != (entry.child_pid, entry.child_uid, entry.child_gid):
            raise AuthorityDenied("native.loader", "loader progress came from another process identity")
        return record

    def _accept_loader_connection(self, entry: _LaunchObservation,
                                  cancelled: Callable[[], bool]) -> None:
        listener = entry.listener_socket
        if listener is None or entry.parent_socket is not None:
            raise AuthorityDenied("native.loader", "root loader listener is unavailable or already consumed")
        while True:
            self._check_deadline(entry, cancelled)
            try:
                readable, _, _ = select.select([listener], [], [],
                                               min(0.1, max(0.0, entry.deadline - self.clock())))
            except (OSError, ValueError):
                raise AuthorityDenied("native.loader", "private loader listener failed") from None
            if not readable:
                continue
            try:
                channel, _peer = listener.accept()
            except OSError:
                raise AuthorityDenied("native.loader", "systemd loader FD could not be accepted") from None
            try:
                # SO_PEERCRED may identify systemd's connection; it is not used
                # as child proof. Every progress recvmsg must carry SCM_CREDENTIALS.
                channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                channel.set_inheritable(False)
                self._assert_current_launch(entry)
                if cancelled():
                    raise AuthorityDenied("native.cancelled", "loader observation was cancelled")
                channel.sendall(entry.launch_nonce.encode("ascii"))
            except BaseException as exc:
                try:
                    channel.close()
                except OSError:
                    pass
                if isinstance(exc, OSError):
                    raise AuthorityDenied("native.loader", "systemd loader FD could not be challenged") from None
                raise
            entry.listener_socket = None
            entry.parent_socket = channel
            listener.close()
            _close_loader_path(None, entry.socket_path, entry.socket_directory)
            return

    def _recv_exact(self, entry: _LaunchObservation, length: int,
                    cancelled: Callable[[], bool]) -> tuple[bytes, tuple[int, int, int]]:
        data = bytearray()
        credentials: tuple[int, int, int] | None = None
        while len(data) < length:
            self._check_deadline(entry, cancelled)
            channel = entry.parent_socket
            if channel is None:
                raise AuthorityDenied("native.loader", "root loader channel was not accepted")
            try:
                readable, _, _ = select.select([channel], [], [],
                                               min(0.1, max(0.0, entry.deadline - self.clock())))
            except (OSError, ValueError):
                raise AuthorityDenied("native.loader", "private loader channel failed") from None
            if not readable:
                continue
            try:
                chunk, ancillary, flags, address = channel.recvmsg(
                    length - len(data), socket.CMSG_SPACE(struct.calcsize("3i")))
            except OSError:
                raise AuthorityDenied("native.loader", "private loader channel read failed") from None
            if flags & getattr(socket, "MSG_CTRUNC", 0):
                raise AuthorityDenied("native.loader", "loader channel ancillary data was truncated")
            if not chunk:
                raise AuthorityDenied("native.loader", "loader closed before completing its progress record")
            credentials_seen = self._last_credentials(ancillary, address)
            if credentials_seen is None:
                raise AuthorityDenied("native.loader", "loader progress lacks kernel sender credentials")
            if credentials is not None and credentials != credentials_seen:
                raise AuthorityDenied("native.loader", "loader frame changed sender credentials")
            credentials = credentials_seen
            if credentials != (entry.child_pid, entry.child_uid, entry.child_gid):
                raise AuthorityDenied("native.loader", "loader progress came from another process identity")
            data.extend(chunk)
            self._assert_current_launch(entry)
        return bytes(data), credentials

    @staticmethod
    def _last_credentials(ancillary: list[tuple[int, int, bytes]],
                          _address: Any) -> tuple[int, int, int] | None:
        if len(ancillary) != 1:
            return None
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == getattr(socket, "SCM_CREDENTIALS", -1):
                if len(value) < struct.calcsize("3i"):
                    return None
                return struct.unpack("3i", value[:struct.calcsize("3i")])
        return None

    def _read_after_ready(self, entry: _LaunchObservation,
                          cancelled: Callable[[], bool]) -> bool:
        while True:
            self._check_deadline(entry, cancelled)
            try:
                readable, _, _ = select.select([entry.parent_socket], [], [],
                                               min(0.1, max(0.0, entry.deadline - self.clock())))
            except (OSError, ValueError):
                raise AuthorityDenied("native.loader", "private loader channel failed after ready") from None
            if not readable:
                continue
            try:
                channel = entry.parent_socket
                if channel is None:
                    raise OSError("accepted loader channel is absent")
                data, ancillary, flags, address = channel.recvmsg(
                    1, socket.CMSG_SPACE(struct.calcsize("3i")))
            except OSError:
                raise AuthorityDenied("native.loader", "private loader channel failed after ready") from None
            if flags & getattr(socket, "MSG_CTRUNC", 0):
                raise AuthorityDenied("native.loader", "post-ready loader credentials were truncated")
            if not data:
                return False
            if self._last_credentials(ancillary, address) != (
                    entry.child_pid, entry.child_uid, entry.child_gid):
                raise AuthorityDenied("native.loader", "post-ready byte came from another process identity")
            return True

    def _validate_progress(self, entry: _LaunchObservation, record: _ProgressRecord,
                           sequence: int, phase: str, previous: _ProgressRecord | None) -> None:
        selected = entry.selection
        if (record.sequence != sequence or record.phase != phase
                or record.launch_nonce != entry.launch_nonce
                or record.package_id != selected.package_id
                or record.generation != selected.generation
                or record.package_generation != selected.package_generation
                or record.entrypoint_sha256 != selected.entrypoint_sha256
                or record.resolver_sha256 != selected.resolver_sha256):
            raise AuthorityDenied("native.loader", "loader progress differs from the selected package sequence")
        role_ids = tuple(role.role_id for role in record.loaded_process_roles)
        if role_ids != tuple(role.role_id for role in selected.process_roles):
            raise AuthorityDenied("native.loader", "loaded module origins do not cover the selected process roles")
        for actual, role in zip(record.loaded_process_roles, selected.process_roles):
            if (actual.module_name != role.module_name
                    or actual.closure_member_path != role.closure_member_path
                    or actual.module_file_sha256 != role.role_sha256):
                raise AuthorityDenied("native.loader", "loaded module origin differs from the protected process role")
        if sequence == 0 and record.registered_registration_ids:
            raise AuthorityDenied("native.loader", "entrypoint import event contains registration claims")
        if sequence == 1 and record.registered_registration_ids != selected.registered_registration_ids:
            raise AuthorityDenied("native.loader", "registered tool table differs from the protected manifest")
        if sequence == 2 and (previous is None
                              or record.registered_registration_ids != previous.registered_registration_ids
                              or record.registered_registration_ids != selected.registered_registration_ids):
            raise AuthorityDenied("native.loader", "ready event changed the registered tool table")
        if sequence > 0 and (previous is None or record.loaded_process_roles != previous.loaded_process_roles):
            raise AuthorityDenied("native.loader", "loaded process-role origins changed after import")

    def _assert_current_launch(self, entry: _LaunchObservation) -> None:
        if (entry.revoked or self._closed or self.clock() >= entry.deadline
                or self._pidfd_target(entry.child_pidfd) != entry.child_pid
                or self._pidfd_exited(entry.child_pidfd)):
            raise AuthorityDenied("native.loader", "loader process or lease is no longer current")
        current = self.custody_resolver.resolve_live_peer(
            entry.child_pid, entry.child_pidfd,
            profile_id=entry.selection.profile_id,
            generation=entry.selection.generation,
        )
        if (current is None or current.kernel_uid != entry.child_uid
                or current.start_ticks != entry.child_start_ticks
                or current.cgroup_identity != entry.child_cgroup
                or current.namespace_identity != entry.child_namespace
                or current.executable_sha256 != getattr(entry.owned_process_handle.profile,
                                                         "artifact_sha256", None)):
            raise AuthorityDenied("native.loader", "loader child identity or namespace changed")

    def _check_deadline(self, entry: _LaunchObservation,
                        cancelled: Callable[[], bool]) -> None:
        self._assert_current_launch(entry)
        if cancelled():
            raise AuthorityDenied("native.cancelled", "loader progress wait was cancelled")

    @staticmethod
    def _pidfd_target(pidfd: int) -> int | None:
        try:
            with open(f"/proc/self/fdinfo/{pidfd}", encoding="ascii") as stream:
                lines = stream.read().splitlines()
        except OSError:
            return None
        for line in lines:
            if line.startswith("Pid:"):
                try:
                    value = int(line.split(":", 1)[1])
                    return value if value > 0 else None
                except ValueError:
                    return None
        return None

    @staticmethod
    def _pidfd_exited(pidfd: int) -> bool:
        try:
            return _pidfd_poll(pidfd)
        except OSError:
            return True

    @staticmethod
    def _close_entry(entry: _LaunchObservation) -> None:
        for channel in (entry.listener_socket, entry.parent_socket):
            try:
                if channel is not None:
                    channel.close()
            except OSError:
                pass
        try:
            os.close(entry.child_pidfd)
        except OSError:
            pass
        _close_loader_path(None, entry.socket_path, entry.socket_directory)


def _pidfd_poll(pidfd: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))


def _verify_mounted_role_module(pid: int, mount_path: str,
                                role: NativeProcessRoleSelection,
                                observed: LoadedProcessRoleObservation
                                ) -> tuple[int, int, str, int] | None:
    """Open the claimed module beneath the live process root without symlinks.

    The loader channel's module origin is only a claim until the root reopens
    that exact normalized closure member under the current PID's root and
    compares filesystem identity and bytes to the protected role artifact.
    """
    if (type(pid) is not int or pid <= 0 or not isinstance(mount_path, str)
            or not mount_path.startswith("/") or "\\" in mount_path):
        return None
    mount_parts = PurePosixPath(mount_path).parts[1:]
    member_parts = PurePosixPath(role.closure_member_path).parts
    if (not mount_parts or any(part in {"", ".", ".."} for part in mount_parts)
            or any(part in {"", ".", ".."} for part in member_parts)):
        return None
    flags_dir = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags_file = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    opened: list[int] = []
    try:
        # `/proc/<pid>/root` is a kernel magic link to the task root; follow
        # that one anchor, then prohibit symlinks for every package component.
        current_fd = os.open(f"/proc/{pid}/root", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        opened.append(current_fd)
        for component in (*mount_parts, *member_parts[:-1]):
            current_fd = os.open(component, flags_dir, dir_fd=current_fd)
            opened.append(current_fd)
        file_fd = os.open(member_parts[-1], flags_file, dir_fd=current_fd)
        opened.append(file_fd)
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
            return None
        digest = hashlib.sha256()
        remaining = info.st_size
        while remaining:
            chunk = os.read(file_fd, min(128 * 1024, remaining))
            if not chunk:
                return None
            digest.update(chunk)
            remaining -= len(chunk)
        observed_digest = digest.hexdigest()
        if ((info.st_dev, info.st_ino) != (observed.module_file_device, observed.module_file_inode)
                or info.st_size != observed.module_file_size_bytes
                or observed_digest != observed.module_file_sha256
                or observed_digest != role.role_sha256):
            return None
        return info.st_dev, info.st_ino, observed_digest, info.st_size
    except OSError:
        return None
    finally:
        for fd in reversed(opened):
            try:
                os.close(fd)
            except OSError:
                pass


def _parse_progress(payload: bytes) -> _ProgressRecord:
    try:
        text = payload.decode("utf-8", "strict")
        raw = json.loads(text, object_pairs_hook=_unique_pairs,
                         parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")))
        if _canonical_json(raw) != payload:
            raise ValueError("noncanonical JSON")
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise AuthorityDenied("native.loader", "loader progress JSON is malformed or noncanonical") from None
    if not isinstance(raw, dict) or set(raw) != _PROGRESS_FIELDS:
        raise AuthorityDenied("native.loader", "loader progress fields are unknown or incomplete")
    if (type(raw["schema"]) is not int or raw["schema"] != 2
            or not _nonce(raw["launch_nonce"])
            or type(raw["sequence"]) is not int or raw["sequence"] not in (0, 1, 2)
            or raw["phase"] not in _PHASES
            or any(not isinstance(raw[key], str) or not raw[key]
                   for key in ("package_id", "generation", "package_generation"))
            or any(not _valid_digest(raw[key]) for key in _DIGEST_FIELDS)
            or not isinstance(raw["registered_registration_ids"], list)
            or len(raw["registered_registration_ids"]) > MAX_ACTIONS
            or any(not _identifier_value(item) for item in raw["registered_registration_ids"])
            or raw["registered_registration_ids"] != sorted(set(raw["registered_registration_ids"]))
            or not isinstance(raw["loaded_process_roles"], list)
            or len(raw["loaded_process_roles"]) > MAX_ACTIONS):
        raise AuthorityDenied("native.loader", "loader progress field types or bounds are invalid")
    roles: list[LoadedProcessRoleObservation] = []
    try:
        for item in raw["loaded_process_roles"]:
            if not isinstance(item, dict) or set(item) != {
                    "role_id", "module_name", "closure_member_path", "module_file_sha256",
                    "module_file_device", "module_file_inode", "module_file_size_bytes"}:
                raise ValueError("invalid loaded role fields")
            roles.append(LoadedProcessRoleObservation(
                item["role_id"], item["module_name"], item["closure_member_path"],
                item["module_file_sha256"], item["module_file_device"],
                item["module_file_inode"], item["module_file_size_bytes"],
            ))
        if tuple(sorted(role.role_id for role in roles)) != tuple(role.role_id for role in roles):
            raise ValueError("loaded roles are not sorted")
        if len({role.role_id for role in roles}) != len(roles):
            raise ValueError("loaded roles are duplicated")
    except (ValueError, TypeError):
        raise AuthorityDenied("native.loader", "loaded process-role origins are malformed") from None
    return _ProgressRecord(raw["launch_nonce"], raw["sequence"], raw["phase"], raw["package_id"],
                           raw["generation"], raw["package_generation"], raw["entrypoint_sha256"],
                           raw["resolver_sha256"], tuple(raw["registered_registration_ids"]),
                           tuple(roles))


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _identifier(value: Any, name: str) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(ord(c) < 0x20 for c in value):
        raise ValueError(f"{name} is invalid")


def _valid_digest(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def _digest(value: Any, name: str) -> None:
    if not _valid_digest(value):
        raise ValueError(f"{name} is not a lowercase SHA-256 digest")


def _nonce(value: Any) -> bool:
    return (isinstance(value, str) and 40 <= len(value) <= 48
            and all(char.isalnum() or char in "-_" for char in value))


def _mount_namespace_inode(identity: Any) -> int:
    namespace = getattr(identity, "namespace_identity", None)
    try:
        parts = dict(item.split(":", 1) for item in namespace.split(";"))
        value = int(parts["mnt"])
    except (AttributeError, ValueError, KeyError):
        raise AuthorityDenied("native.namespace", "root mount namespace identity is malformed") from None
    if value <= 0:
        raise AuthorityDenied("native.namespace", "root mount namespace identity is invalid")
    return value


def _closed_socket() -> socket.socket:
    """Return a harmless already-closed socket placeholder for a retired entry."""
    result = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    result.close()
    return result


def _close_loader_path(listener: socket.socket | None, socket_path: Path,
                       socket_directory: Path) -> None:
    if listener is not None:
        try:
            listener.close()
        except OSError:
            pass
    if socket_path.parent != socket_directory or socket_path.name != "progress.sock":
        return
    try:
        info = socket_path.lstat()
        if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid():
            socket_path.unlink()
    except OSError:
        pass
    try:
        info = socket_directory.lstat()
        if (stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700):
            socket_directory.rmdir()
    except OSError:
        pass
