"""Root-local admission and currentness for enrolled remote service startup.

This module deliberately separates the process which is allowed to request a
setup effect from the selected service subject that receives it.  The setup
controller is retained through a live PIDFD proof; selected service identities
come only from the protected active enrollment snapshot.
"""
from __future__ import annotations

import hashlib
import os
import re
import select
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .types import AuthorityDenied, canonical_bytes

_OPAQUE = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ROLES = frozenset({"display", "gateway", "desktop"})
_STARTUP_OPERATIONS = {
    "display": "native-display-start-v1",
    "gateway": "native-remote-gateway-start-v1",
    "desktop": "native-desktop-app-start-v1",
}
_ACTIONS = frozenset({"start", "status", "stop"})
_ACTION_OPERATIONS = {
    "start": "process.start",
    "status": "process.status",
    "stop": "process.stop",
}


class SelectedStartupDenied(AuthorityDenied):
    """Selected service startup is not currently authorized."""

    def __init__(self, message: str):
        super().__init__("selected.startup", message)


@dataclass(frozen=True, slots=True, repr=False)
class RootControllerProcessIdentityLease:
    """Caller-owned duplicate of the actual root setup controller PIDFD.

    The `current_check` closure is installed only by the root admission
    registry.  Custody independently checks the kernel identity and calls
    ``is_current`` immediately before its effect.
    """

    proof_handle: str
    startup_authorization_handle: str
    pid: int
    uid: int
    start_ticks: int
    pidfd: int = field(repr=False)
    cgroup_identity: str
    mount_namespace_inode: int
    network_namespace_inode: int
    proof_sha256: str
    expires_monotonic: float
    _current_check: Callable[[], bool] = field(repr=False, compare=False)
    _monotonic: Callable[[], float] = field(default=time.monotonic, repr=False, compare=False)
    _closed: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.proof_handle)
                or not _OPAQUE.fullmatch(self.startup_authorization_handle)
                or type(self.pid) is not int or self.pid <= 0
                or type(self.uid) is not int or self.uid != 0
                or type(self.start_ticks) is not int or self.start_ticks <= 0
                or type(self.pidfd) is not int or self.pidfd < 0
                or not isinstance(self.cgroup_identity, str) or not self.cgroup_identity.startswith("/")
                or type(self.mount_namespace_inode) is not int or self.mount_namespace_inode <= 0
                or type(self.network_namespace_inode) is not int or self.network_namespace_inode <= 0
                or not _DIGEST.fullmatch(self.proof_sha256)
                or isinstance(self.expires_monotonic, bool)
                or type(self.expires_monotonic) not in (int, float)
                or self.expires_monotonic <= 0 or not callable(self._current_check)):
            raise SelectedStartupDenied("selected startup controller PIDFD proof is malformed")

    def is_current(self) -> bool:
        if self._closed or self._monotonic() >= self.expires_monotonic:
            return False
        poller = select.poll()
        try:
            poller.register(self.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            if poller.poll(0):
                return False
            return (RootSelectedDisplayLaunchAuthority._pidfd_matches(self.pidfd, self.pid)
                    and bool(self._current_check()))
        except (OSError, ValueError, PermissionError):
            return False

    def close(self) -> None:
        if not self._closed:
            object.__setattr__(self, "_closed", True)
            try:
                os.close(self.pidfd)
            except OSError:
                pass

    def __repr__(self) -> str:
        return "RootControllerProcessIdentityLease(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedStartupRoleBinding:
    """One active role's protected process recipe and service identity."""

    role: str
    action: str
    service_enrollment_id: str
    profile_id: str
    generation: str
    principal_id: str
    namespace_identity: str
    subject_uid: int
    subject_gid: int
    operation_id: str
    operation: str
    capability: str
    target: str
    recipe_sha256: str
    source_closure_sha256: str
    source_receipt_handles: tuple[str, ...]
    service_profile: Any = field(repr=False, compare=False)
    process_operation: Any = field(repr=False, compare=False)
    source_closure: Any = field(repr=False, compare=False)
    process_id: str | None = field(default=None, repr=False)
    stop_reason: str | None = field(default=None, repr=False)
    stop_grace_seconds: int = field(default=5, repr=False)

    def __post_init__(self) -> None:
        expected_capability = ("hermes-profile-invoke" if self.action == "start"
                               else "hermes-process-control")
        if (self.role not in _ROLES
                or self.action not in _ACTIONS
                or (self.action == "start" and self.operation_id != _STARTUP_OPERATIONS[self.role])
                or self.operation != _ACTION_OPERATIONS.get(self.action)
                or self.capability != expected_capability
                or not all(isinstance(value, str) and value for value in (
                    self.service_enrollment_id, self.profile_id, self.generation,
                    self.principal_id, self.namespace_identity, self.target))
                or type(self.subject_uid) is not int or self.subject_uid <= 0
                or type(self.subject_gid) is not int or self.subject_gid <= 0
                or not _DIGEST.fullmatch(self.recipe_sha256)
                or not _DIGEST.fullmatch(self.source_closure_sha256)
                or not isinstance(self.source_receipt_handles, tuple)
                or (self.action != "start" and (not isinstance(self.process_id, str)
                                                 or not self.process_id))
                or (self.action == "stop" and self.stop_reason not in {
                    "cancel", "shutdown", "rollback"})
                or (self.action != "stop" and self.stop_reason is not None)
                or type(self.stop_grace_seconds) is not int
                or not 0 <= self.stop_grace_seconds <= 10
                or self.service_profile is None or self.process_operation is None
                or self.source_closure is None):
            raise SelectedStartupDenied("selected startup role binding is malformed")

    def __repr__(self) -> str:
        return f"RootSelectedStartupRoleBinding(role={self.role!r}, <root-private>)"

    def payload(self) -> bytes:
        """Canonical bytes are derived solely from this retained action binding."""
        return startup_selection_payload(self)


@dataclass(frozen=True, slots=True, repr=False)
class SelectedStartupSelection:
    """Typed selected display projection passed to the Xpra patch registry."""

    selected_startup_enrollment_id: str
    remote_enrollment_id: str
    display_enrollment_id: str
    display_generation: str
    display_operation_id: str
    service_generation_digest: str
    overlay_artifact_id: str
    overlay_sha256: str
    patch_receipt_handle: str
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (not all(isinstance(value, str) and value for value in (
                    self.selected_startup_enrollment_id, self.remote_enrollment_id,
                    self.display_enrollment_id, self.display_generation,
                    self.display_operation_id, self.overlay_artifact_id,
                    self.patch_receipt_handle))
                or self.display_operation_id != _STARTUP_OPERATIONS["display"]
                or not _DIGEST.fullmatch(self.service_generation_digest)
                or not _DIGEST.fullmatch(self.overlay_sha256)
                or not _OPAQUE.fullmatch(self.patch_receipt_handle)
                or isinstance(self.expires_monotonic, bool)
                or type(self.expires_monotonic) not in (int, float)
                or self.expires_monotonic <= 0 or self._seal is None):
            raise SelectedStartupDenied("selected Xpra patch selection is malformed")

    @property
    def process_generation(self) -> str:
        """Compatibility spelling used by the overlay receipt join."""
        return self.display_generation

    def __repr__(self) -> str:
        return "SelectedStartupSelection(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedDisplayStartReceipt:
    """Root-retained result of actual selected display launch and Xauth seal."""

    admission_handle: str
    process_receipt: Any = field(repr=False, compare=False)
    xauthority_receipt: Any = field(repr=False, compare=False)
    overlay_receipt: Any = field(repr=False, compare=False)
    selection: SelectedStartupSelection = field(repr=False, compare=False)
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.admission_handle)
                or type(self.selection) is not SelectedStartupSelection
                or self.process_receipt is None or self.xauthority_receipt is None
                or self.overlay_receipt is None or self._seal is None
                or type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or self.expires_monotonic <= self.issued_monotonic):
            raise SelectedStartupDenied("selected display start receipt is malformed")

    def __repr__(self) -> str:
        return "RootSelectedDisplayStartReceipt(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedServiceHealthControl:
    """Retained status observation of one actual root-managed selected process."""

    admission_handle: str
    role: str
    process_id: str
    generation: str
    observed_monotonic: float
    status_receipt: Any = field(repr=False, compare=False)
    _authority: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.admission_handle)
                or self.role not in _ROLES
                or not isinstance(self.process_id, str) or not self.process_id
                or not isinstance(self.generation, str) or not self.generation
                or isinstance(self.observed_monotonic, bool)
                or type(self.observed_monotonic) not in (int, float)
                or self.status_receipt is None or self._authority is None or self._seal is None):
            raise SelectedStartupDenied("selected service health control is malformed")

    @property
    def state(self) -> str:
        return self.status_receipt.state

    @property
    def exit_code(self) -> int | None:
        return self.status_receipt.exit_code

    def is_current(self) -> bool:
        check = getattr(self._authority, "_health_control_current", None)
        return bool(callable(check) and check(self, self._seal))

    def __repr__(self) -> str:
        return "RootSelectedServiceHealthControl(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootVerifiedStartupAdmission:
    """In-memory sealed active selection, setup controller, and source closure.

    A handle is useful only in the registry instance that created it. The
    private seal and retained selection/source objects are never serialized.
    """

    admission_handle: str
    remote_enrollment_id: str
    selected_startup_enrollment_id: str
    service_generation_digest: str
    controller_proof_handle: str
    controller_proof_sha256: str
    selected_startup: SelectedStartupSelection = field(repr=False)
    role_bindings: Mapping[str, RootSelectedStartupRoleBinding] = field(repr=False)
    issued_monotonic: float
    expires_monotonic: float
    _instance_seal: object = field(repr=False, compare=False)
    _setup_session_handle: Any = field(repr=False, compare=False)
    _setup_operation_intent: str = field(repr=False, compare=False)
    _selected_startup_row: Any = field(repr=False, compare=False)
    _network_row: Any = field(repr=False, compare=False)
    _display_startup: Any = field(repr=False, compare=False)
    _controller_lease: RootControllerProcessIdentityLease = field(repr=False, compare=False)
    _xauthority_registry: Any = field(repr=False, compare=False)
    _overlay_registry: Any = field(repr=False, compare=False)
    _source_closure: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.admission_handle)
                or not all(isinstance(value, str) and value for value in (
                    self.remote_enrollment_id, self.selected_startup_enrollment_id,
                    self.controller_proof_handle))
                or not _DIGEST.fullmatch(self.service_generation_digest)
                or not _DIGEST.fullmatch(self.controller_proof_sha256)
                or type(self.selected_startup) is not SelectedStartupSelection
                or self.selected_startup.service_generation_digest != self.service_generation_digest
                or self.selected_startup.remote_enrollment_id != self.remote_enrollment_id
                or self.selected_startup.selected_startup_enrollment_id != self.selected_startup_enrollment_id
                or not isinstance(self.role_bindings, Mapping)
                or set(self.role_bindings) != _ROLES
                or any(type(binding) is not RootSelectedStartupRoleBinding
                       or binding.role != role for role, binding in self.role_bindings.items())
                or isinstance(self.issued_monotonic, bool)
                or type(self.issued_monotonic) not in (int, float)
                or isinstance(self.expires_monotonic, bool)
                or type(self.expires_monotonic) not in (int, float)
                or self.expires_monotonic <= self.issued_monotonic
                or self._instance_seal is None
                or not isinstance(self._controller_lease, RootControllerProcessIdentityLease)):
            raise SelectedStartupDenied("root selected startup admission is malformed")
        object.__setattr__(self, "role_bindings", MappingProxyType(dict(self.role_bindings)))

    def __repr__(self) -> str:
        return "RootVerifiedStartupAdmission(<root-private>)"


def startup_selection_payload(binding: RootSelectedStartupRoleBinding) -> bytes:
    """Canonical payload for one fixed selected role action."""
    if type(binding) is not RootSelectedStartupRoleBinding:
        raise SelectedStartupDenied("typed root selected startup role binding is required")
    if binding.action == "start":
        return canonical_bytes({
            "schema": 1,
            "enrollment_id": binding.service_enrollment_id,
            "generation": binding.generation,
            "operation_id": binding.operation_id,
            "parameters": {},
        })
    process_id = getattr(binding, "process_id", None)
    if not isinstance(process_id, str) or not process_id:
        raise SelectedStartupDenied("selected process control requires a retained root process handle")
    payload = {"schema": 1, "process_id": process_id, "generation": binding.generation}
    if binding.action == "stop":
        # Root derives the normal shutdown verb; cancellation and partial-start
        # rollback use distinct root-only call paths and cannot be requested by
        # an RPC caller.
        payload.update(reason=binding.stop_reason, grace_seconds=binding.stop_grace_seconds)
    return canonical_bytes(payload)


class RootSelectedDisplayLaunchAuthority:
    """Issue and consume finite role grants for the exact selected remote row.

    All retained objects are constructed from the already verified root
    runtime.  This class is intentionally not a worker-facing transport.
    """

    def __init__(self, *, active_bindings: Any,
                 verified_root_setup_sessions: Any, authority_service: Any,
                 custody: Any, xauthority_registry: Any,
                 overlay_registry: Any, root_journal: Any,
                 monotonic: Callable[[], float] = time.monotonic):
        from .bootstrap_enrollment import RootSetupSessionStore
        from .native_display_startup import XauthorityStartupRegistry
        from hermes_installer.managed_process_custodian import ManagedProcessEffectHandler

        if (active_bindings is None
                or not isinstance(verified_root_setup_sessions, RootSetupSessionStore)
                or authority_service is None
                or not isinstance(custody, ManagedProcessEffectHandler)
                or not isinstance(xauthority_registry, XauthorityStartupRegistry)
                or not callable(getattr(active_bindings, "resolve_remote_startup", None))
                or not callable(getattr(active_bindings, "resolve_private_loopback_network", None))
                or not callable(getattr(active_bindings, "resolve_selected_native_principal", None))
                or not callable(getattr(active_bindings, "resolve_selected_operation", None))
                or not callable(getattr(overlay_registry, "resolve_selected_patch", None))
                or not callable(monotonic)):
            raise SelectedStartupDenied("verified selected-startup runtime dependencies are incomplete")
        self.active_bindings = active_bindings
        self.setup_sessions = verified_root_setup_sessions
        self.authority_service = authority_service
        self.custody = custody
        self.xauthority_registry = xauthority_registry
        self.overlay_registry = overlay_registry
        self.root_journal = root_journal
        self.monotonic = monotonic
        self._lock = threading.RLock()
        self._admissions: dict[str, RootVerifiedStartupAdmission] = {}
        self._controller_pidfds: dict[str, int] = {}
        self._used_role_actions: set[tuple[str, str, str]] = set()
        self._started_processes: dict[tuple[str, str], Any] = {}
        self._prepared_xauthority: dict[str, Any] = {}
        self._display_start_receipts: dict[str, RootSelectedDisplayStartReceipt] = {}
        self._health_controls: dict[tuple[str, str], RootSelectedServiceHealthControl] = {}

    @classmethod
    def from_root_runtime(cls, active_bindings: Any,
                          verified_root_setup_sessions: Any,
                          authority_service: Any, custody: Any,
                          xauthority_registry: Any, root_journal: Any,
                          overlay_registry: Any, *,
                          monotonic: Callable[[], float] = time.monotonic
                          ) -> "RootSelectedDisplayLaunchAuthority":
        """Explicit constructor used by the verified root-runtime factory."""
        return cls(
            active_bindings=active_bindings,
            verified_root_setup_sessions=verified_root_setup_sessions,
            authority_service=authority_service, custody=custody,
            xauthority_registry=xauthority_registry,
            overlay_registry=overlay_registry, root_journal=root_journal,
            monotonic=monotonic,
        )

    def admit_selected_start(self, setup_session_handle: Any,
                             remote_enrollment_id: str) -> str:
        """Retain a current root setup actor and one explicitly selected row."""
        from .bootstrap_enrollment import RootSetupSessionHandle

        if (os.name != "posix" or not sys_platform_linux()
                or os.geteuid() != 0
                or not isinstance(setup_session_handle, RootSetupSessionHandle)
                or not isinstance(remote_enrollment_id, str) or not remote_enrollment_id):
            raise SelectedStartupDenied("root selected startup setup session is unavailable")
        try:
            operation_intent = self.setup_sessions.operation_intent(setup_session_handle)
            # The setup session owns the only authoritative wall-clock lease.
            # Do not replace it with a fresh ten-minute startup lease: a
            # selected service admission must expire no later than its parent
            # root setup transaction.
            setup_live = self.setup_sessions._live(setup_session_handle)
            setup_deadline = setup_live.record.get("expires_monotonic")
            if (isinstance(setup_deadline, bool)
                    or type(setup_deadline) not in (int, float)
                    or setup_deadline <= self.monotonic()):
                raise SelectedStartupDenied("root setup session deadline is unavailable")
            service_digest = self._service_generation_digest()
            selected_row = self.active_bindings.resolve_remote_startup(remote_enrollment_id)
            network_row = self.active_bindings.resolve_private_loopback_network(
                selected_row.network_enrollment_id,
                service_generation_digest=service_digest,
            )
            selection = self._resolve_selection(remote_enrollment_id, selected_row, network_row)
            actor_pidfd = os.pidfd_open(os.getpid(), 0)
            identity = self._controller_identity(os.getpid())
        except Exception:
            raise SelectedStartupDenied("current root setup or selected startup enrollment is unavailable") from None
        try:
            if not self._pidfd_matches(actor_pidfd, identity["pid"]):
                raise SelectedStartupDenied("root setup controller PIDFD is not current")
            now = self.monotonic()
            expires = min(now + 600.0, float(setup_deadline),
                          float(getattr(selected_row, "expires_monotonic", now + 600.0)))
            if expires <= now:
                raise SelectedStartupDenied("selected startup admission deadline is expired")
            proof_handle = secrets.token_urlsafe(32)
            startup_handle = secrets.token_urlsafe(32)
            controller_digest = hashlib.sha256(canonical_bytes({
                "pid": identity["pid"], "uid": identity["uid"],
                "start_ticks": identity["start_ticks"],
                "cgroup_identity": identity["cgroup_identity"],
                "mount_namespace_inode": identity["mount_namespace_inode"],
                "network_namespace_inode": identity["network_namespace_inode"],
                "setup_operation_intent": operation_intent,
            })).hexdigest()
            proof = RootControllerProcessIdentityLease(
                proof_handle=proof_handle,
                startup_authorization_handle=startup_handle,
                pid=identity["pid"], uid=identity["uid"],
                start_ticks=identity["start_ticks"], pidfd=os.dup(actor_pidfd),
                cgroup_identity=identity["cgroup_identity"],
                mount_namespace_inode=identity["mount_namespace_inode"],
                network_namespace_inode=identity["network_namespace_inode"],
                proof_sha256=controller_digest,
                expires_monotonic=expires,
                _current_check=lambda: self._setup_controller_current(
                    setup_session_handle, operation_intent, identity,
                ),
                _monotonic=self.monotonic,
            )
        finally:
            os.close(actor_pidfd)
        try:
            role_bindings = self._resolve_role_bindings(selected_row, selection, service_digest)
            selected_startup = SelectedStartupSelection(
                selected_startup_enrollment_id=selected_row.id,
                remote_enrollment_id=remote_enrollment_id,
                display_enrollment_id=role_bindings["display"].service_enrollment_id,
                display_generation=role_bindings["display"].generation,
                display_operation_id=role_bindings["display"].operation_id,
                service_generation_digest=service_digest,
                overlay_artifact_id=selected_row.xpra_xauthority_overlay_artifact_id,
                overlay_sha256=selected_row.xpra_xauthority_overlay_sha256,
                patch_receipt_handle=selected_row.xpra_xauthority_patch_receipt_handle,
                expires_monotonic=expires, _seal=object(),
            )
            closure = tuple(binding.source_closure for binding in role_bindings.values())
            closure_digest = hashlib.sha256(canonical_bytes([
                binding.source_closure_sha256 for binding in role_bindings.values()
            ])).hexdigest()
            admission_handle = secrets.token_urlsafe(32)
            admission = RootVerifiedStartupAdmission(
                admission_handle=admission_handle,
                remote_enrollment_id=remote_enrollment_id,
                selected_startup_enrollment_id=selected_row.id,
                service_generation_digest=service_digest,
                controller_proof_handle=proof_handle,
                controller_proof_sha256=controller_digest,
                selected_startup=selected_startup,
                role_bindings=role_bindings,
                issued_monotonic=now, expires_monotonic=expires,
                _instance_seal=object(),
                _setup_session_handle=setup_session_handle,
                _setup_operation_intent=operation_intent,
                _selected_startup_row=selected_row,
                _network_row=network_row,
                _display_startup=selection,
                _controller_lease=proof,
                _xauthority_registry=self.xauthority_registry,
                _overlay_registry=self.overlay_registry,
                _source_closure=(closure, closure_digest),
            )
        except Exception:
            proof.close()
            raise
        with self._lock:
            if admission_handle in self._admissions:
                proof.close()
                raise SelectedStartupDenied("startup admission handle collision")
            self._admissions[admission_handle] = admission
            self._controller_pidfds[proof_handle] = os.dup(proof.pidfd)
        return admission_handle

    def resolve_current_admission(self, admission_handle: str) -> RootVerifiedStartupAdmission:
        if not isinstance(admission_handle, str) or not _OPAQUE.fullmatch(admission_handle):
            raise SelectedStartupDenied("selected startup admission handle is invalid")
        with self._lock:
            admission = self._admissions.get(admission_handle)
        if (type(admission) is not RootVerifiedStartupAdmission
                or admission._instance_seal is None
                or self.monotonic() >= admission.expires_monotonic
                or not self.is_current(admission)):
            raise SelectedStartupDenied("selected root startup admission is stale or unavailable")
        return admission

    def resolve_startup_controller_proof(self, controller_proof_handle: str,
                                         startup_authorization_handle: str
                                         ) -> RootControllerProcessIdentityLease:
        admission = self.resolve_current_admission(startup_authorization_handle)
        if admission.controller_proof_handle != controller_proof_handle:
            raise SelectedStartupDenied("startup controller proof belongs to another admission")
        proof = admission._controller_lease
        if not proof.is_current():
            raise SelectedStartupDenied("startup controller PIDFD proof is no longer current")
        with self._lock:
            retained = self._controller_pidfds.get(controller_proof_handle)
        if retained is None:
            raise SelectedStartupDenied("startup controller PIDFD proof was revoked")
        try:
            return RootControllerProcessIdentityLease(
                proof_handle=proof.proof_handle,
                startup_authorization_handle=proof.startup_authorization_handle,
                pid=proof.pid, uid=proof.uid, start_ticks=proof.start_ticks,
                pidfd=os.dup(retained), cgroup_identity=proof.cgroup_identity,
                mount_namespace_inode=proof.mount_namespace_inode,
                network_namespace_inode=proof.network_namespace_inode,
                proof_sha256=proof.proof_sha256,
                expires_monotonic=proof.expires_monotonic,
                _current_check=proof._current_check, _monotonic=self.monotonic,
            )
        except OSError:
            raise SelectedStartupDenied("startup controller PIDFD could not be duplicated") from None

    def resolve_selected_recipe_binding(self, admission: RootVerifiedStartupAdmission,
                                        role: str, action: str = "start", *,
                                        _stop_reason: str = "shutdown"
                                        ) -> RootSelectedStartupRoleBinding:
        current = self.resolve_current_admission(admission.admission_handle)
        if current is not admission or role not in _ROLES or action not in _ACTIONS:
            raise SelectedStartupDenied("selected startup role is outside the retained admission")
        start_binding = admission.role_bindings[role]
        if not self._role_binding_current(admission._selected_startup_row, start_binding):
            raise SelectedStartupDenied("selected service recipe or source closure changed")
        if action == "start":
            return start_binding
        process_id = self._retained_process_id(admission, role)
        operation_name = _ACTION_OPERATIONS[action]
        target = start_binding.service_profile.operation_targets.get(operation_name)
        if not isinstance(target, str) or not target:
            raise SelectedStartupDenied("selected process control target is not protected")
        operation_type = type(start_binding.process_operation)
        process_operation = operation_type(
            operation=operation_name, operation_id=operation_name, target=target,
            enrollment_id=start_binding.service_enrollment_id,
            generation=start_binding.generation, profile_id=start_binding.profile_id,
            principal_id=start_binding.principal_id,
            service_uid=start_binding.subject_uid, service_gid=start_binding.subject_gid,
        )
        control_recipe = {
            "operation": operation_name, "target": target,
            "enrollment_id": start_binding.service_enrollment_id,
            "generation": start_binding.generation,
        }
        return RootSelectedStartupRoleBinding(
            role=role, action=action,
            service_enrollment_id=start_binding.service_enrollment_id,
            profile_id=start_binding.profile_id, generation=start_binding.generation,
            principal_id=start_binding.principal_id,
            namespace_identity=start_binding.namespace_identity,
            subject_uid=start_binding.subject_uid, subject_gid=start_binding.subject_gid,
            operation_id=operation_name, operation=operation_name,
            capability="hermes-process-control", target=target,
            recipe_sha256=hashlib.sha256(canonical_bytes(control_recipe)).hexdigest(),
            source_closure_sha256=start_binding.source_closure_sha256,
            source_receipt_handles=start_binding.source_receipt_handles,
            process_id=process_id, service_profile=start_binding.service_profile,
            process_operation=process_operation,
            source_closure=start_binding.source_closure,
            stop_reason=_stop_reason if action == "stop" else None,
        )

    def is_current(self, admission: RootVerifiedStartupAdmission) -> bool:
        if (type(admission) is not RootVerifiedStartupAdmission
                or self.monotonic() >= admission.expires_monotonic
                or not admission._controller_lease.is_current()):
            return False
        try:
            intent = self.setup_sessions.operation_intent(admission._setup_session_handle)
            if intent != admission._setup_operation_intent:
                return False
            current_digest = self._service_generation_digest()
            row = self.active_bindings.resolve_remote_startup(admission.remote_enrollment_id)
            network = self.active_bindings.resolve_private_loopback_network(
                row.network_enrollment_id,
                service_generation_digest=current_digest,
            )
            if (row.id != admission.selected_startup_enrollment_id
                    or row != admission._selected_startup_row
                    or current_digest != admission.service_generation_digest
                    or network != admission._network_row
                    or not self._network_row_current(network, admission.role_bindings)):
                return False
            for role, binding in admission.role_bindings.items():
                if not self._role_binding_current(row, binding):
                    return False
            self._resolve_overlay_receipt(row, admission)
            return True
        except Exception:
            return False

    def issue_role_grant(self, admission_handle: str, role: str,
                         action: str = "start", *,
                         _stop_reason: str = "shutdown") -> Any:
        """Issue one service-owned signed grant for one exact role action."""
        if action not in _ACTIONS or role not in _ROLES:
            raise SelectedStartupDenied("startup action is outside the finite role/action set")
        admission = self.resolve_current_admission(admission_handle)
        binding = self.resolve_selected_recipe_binding(admission, role, action,
                                                       _stop_reason=_stop_reason)
        payload = startup_selection_payload(binding)
        with self._lock:
            key = (admission_handle, role, action)
            if action != "status" and key in self._used_role_actions:
                raise SelectedStartupDenied("selected role start action was already issued")
            if action != "status":
                self._used_role_actions.add(key)
        try:
            return self.authority_service.issue_root_selected_service_effect(
                admission, binding, action, payload,
            )
        except Exception:
            with self._lock:
                self._used_role_actions.discard(key)
            raise

    def consume_role_grant(self, grant: Any, admission_handle: str,
                           role: str, action: str = "start", *,
                           _stop_reason: str = "shutdown") -> Any:
        admission = self.resolve_current_admission(admission_handle)
        binding = self.resolve_selected_recipe_binding(admission, role, action,
                                                       _stop_reason=_stop_reason)
        payload = startup_selection_payload(binding)
        return self.authority_service.consume_root_selected_service_effect(
            grant, admission, binding.service_profile, payload,
        )

    def start_selected_role(self, admission_handle: str, role: str, *,
                            timeout: float = 30.0,
                            cancelled: Callable[[], bool] | None = None) -> Any:
        """Issue, consume, and perform one root-only enrolled role start."""
        cancelled = cancelled or (lambda: False)
        if (isinstance(timeout, bool) or type(timeout) not in (int, float)
                or not 0 < timeout <= 600 or cancelled()):
            raise SelectedStartupDenied("selected startup request bounds are invalid")
        admission = self.resolve_current_admission(admission_handle)
        if role == "display":
            with self._lock:
                prepared = self._prepared_xauthority.get(admission_handle)
            if prepared is None:
                raise SelectedStartupDenied("display launch requires root-prepared Xauthority")
        elif role in {"gateway", "desktop"}:
            start_receipt = self._display_start_receipts.get(admission_handle)
            if not self._display_receipt_current(admission, start_receipt):
                raise SelectedStartupDenied("gateway/Desktop launch requires current selected display receipt")
        binding = self.resolve_selected_recipe_binding(admission, role, "start")
        grant = self.issue_role_grant(admission_handle, role)
        verified = self.consume_role_grant(grant, admission_handle, role)
        proof = self.resolve_startup_controller_proof(
            admission.controller_proof_handle, admission_handle,
        )
        try:
            if cancelled() or not proof.is_current():
                raise SelectedStartupDenied("selected startup controller changed before custody effect")
            binding = self.resolve_selected_recipe_binding(admission, role, "start")
            mount = self._selected_xauthority_binding(admission, role)
            result = self.custody.perform_root_selected_service_effect(
                binding.service_profile, verified, startup_selection_payload(binding),
                timeout=min(float(timeout), admission.expires_monotonic - self.monotonic()),
                cancelled=cancelled,
                controller_proof=proof,
                xauthority_binding=mount,
                overlay_binding=(self._resolve_overlay_receipt(admission._selected_startup_row, admission)
                                if role == "display" else None),
            )
            process_id = getattr(result, "process_id", None)
            generation = getattr(result, "generation", None)
            if (not isinstance(process_id, str) or not process_id
                    or generation != binding.generation):
                raise SelectedStartupDenied("custody returned no typed selected process receipt")
            with self._lock:
                self._started_processes[(admission_handle, role)] = result
            return result
        finally:
            proof.close()

    def start_selected_display(self, admission_handle: str, *,
                               timeout: float = 30.0,
                               cancelled: Callable[[], bool] | None = None
                               ) -> RootSelectedDisplayStartReceipt:
        """Production callpoint: prepare cookie, verify patch, launch, then seal."""
        from .native_display_startup import XauthorityStartupRegistry

        admission = self.resolve_current_admission(admission_handle)
        if not isinstance(admission._xauthority_registry, XauthorityStartupRegistry):
            raise SelectedStartupDenied("selected Xauthority registry is unavailable")
        with self._lock:
            if admission_handle in self._display_start_receipts:
                raise SelectedStartupDenied("selected display already has a retained start receipt")
        overlay_receipt = self._resolve_overlay_receipt(
            admission._selected_startup_row, admission,
        )
        prepared = admission._xauthority_registry.prepare(admission._display_startup)
        with self._lock:
            self._prepared_xauthority[admission_handle] = prepared
        process_receipt = None
        try:
            process_receipt = self.start_selected_role(
                admission_handle, "display", timeout=timeout, cancelled=cancelled,
            )
            xauthority_receipt = admission._xauthority_registry.seal_started_display(prepared)
            if (getattr(process_receipt, "process_id", None) != xauthority_receipt.process_id
                    or getattr(process_receipt, "generation", None) != xauthority_receipt.process_generation
                    or not self._role_binding_current(
                        admission._selected_startup_row, admission.role_bindings["display"]
                    )):
                raise SelectedStartupDenied("Xauthority seal does not join the actual selected display launch")
            receipt = RootSelectedDisplayStartReceipt(
                admission_handle=admission_handle,
                process_receipt=process_receipt,
                xauthority_receipt=xauthority_receipt,
                overlay_receipt=overlay_receipt,
                selection=admission.selected_startup,
                issued_monotonic=self.monotonic(),
                expires_monotonic=min(
                    admission.expires_monotonic,
                    getattr(process_receipt, "expires_monotonic", admission.expires_monotonic),
                    getattr(xauthority_receipt, "expires_monotonic", admission.expires_monotonic),
                ),
                _seal=object(),
            )
            with self._lock:
                self._display_start_receipts[admission_handle] = receipt
            return receipt
        except BaseException:
            if process_receipt is not None:
                self._stop_selected_role_for_cleanup(admission, "display", process_receipt)
            admission._xauthority_registry.discard_prepared(prepared)
            raise

    def resolve_live_health_control(self, admission_handle: str,
                                    role: str) -> "RootSelectedServiceHealthControl":
        """Produce health only from a fresh exact status effect on a retained launch."""
        if role not in _ROLES:
            raise SelectedStartupDenied("selected health role is outside the fixed set")
        admission = self.resolve_current_admission(admission_handle)
        if role in {"gateway", "desktop"}:
            display = self._display_start_receipts.get(admission_handle)
            if (display is None or display.selection != admission.selected_startup
                    or not self._display_receipt_current(admission, display)):
                raise SelectedStartupDenied("selected display/Xauthority predecessor is not current")
        result = self.control_selected_role(admission_handle, role, "status")
        if not self._is_typed_live_status_result(result, admission, role):
            raise SelectedStartupDenied("custody returned no typed live managed-process status")
        retained = self._started_processes.get((admission_handle, role))
        control = RootSelectedServiceHealthControl(
            admission_handle=admission_handle, role=role,
            process_id=self._retained_process_id(admission, role),
            generation=admission.role_bindings[role].generation,
            observed_monotonic=self.monotonic(), status_receipt=result,
            _authority=self, _seal=object(),
        )
        with self._lock:
            self._health_controls[(admission_handle, role)] = control
        return control

    def _stop_selected_role_for_cleanup(self, admission: RootVerifiedStartupAdmission,
                                        role: str, process_receipt: Any) -> None:
        """Rollback only the exact process successfully retained by custody."""
        with self._lock:
            current = self._started_processes.get((admission.admission_handle, role))
        if current is not process_receipt:
            return
        try:
            self.control_selected_role(
                admission.admission_handle, role, "stop", timeout=10.0,
                _stop_reason="rollback",
            )
        except Exception:
            # Retain the receipt for custody's exact owned-process cleanup.
            return

    def _health_control_current(self, control: RootSelectedServiceHealthControl,
                                seal: object) -> bool:
        if (type(control) is not RootSelectedServiceHealthControl
                or control._authority is not self or control._seal is not seal):
            return False
        with self._lock:
            if self._health_controls.get((control.admission_handle, control.role)) is not control:
                return False
            process_receipt = self._started_processes.get((control.admission_handle, control.role))
        try:
            admission = self.resolve_current_admission(control.admission_handle)
            if (process_receipt is None
                    or getattr(process_receipt, "process_id", None) != control.process_id
                    or getattr(process_receipt, "generation", None) != control.generation
                    or not self._is_typed_live_status_result(
                        control.status_receipt, admission, control.role,
                    )):
                return False
            lease_resolver = getattr(self.custody, "resolve_selected_service_process", None)
            if not callable(lease_resolver):
                return False
            lease = lease_resolver(process_receipt)
            if lease is None:
                return False
            try:
                return (lease.process_id == control.process_id
                        and lease.generation == control.generation
                        and self.monotonic() < process_receipt.expires_monotonic)
            finally:
                lease.close()
        except Exception:
            return False

    def _is_typed_live_status_result(self, result: Any,
                                     admission: RootVerifiedStartupAdmission,
                                     role: str) -> bool:
        from hermes_installer.managed_process_custodian import RootSelectedServiceStatusReceipt

        with self._lock:
            retained = self._started_processes.get((admission.admission_handle, role))
        return bool(
            type(result) is RootSelectedServiceStatusReceipt
            and result.schema == 1
            and _OPAQUE.fullmatch(result.receipt_handle)
            and retained is not None
            and result.process_receipt is retained
            and result.process_receipt.profile_id == admission.role_bindings[role].profile_id
            and result.process_receipt.generation == admission.role_bindings[role].generation
            and result.service_generation_digest == admission.service_generation_digest
            and result.observed_monotonic <= self.monotonic()
            and self.monotonic() < result.process_receipt.expires_monotonic
            and _DIGEST.fullmatch(result.process_identity_digest)
            and result.process_identity_digest == result.process_receipt.process_identity_digest
            and result.state in {"running", "stopped", "exited"}
            and (result.exit_code is None or type(result.exit_code) is int)
        )

    def _display_receipt_current(self, admission: RootVerifiedStartupAdmission,
                                 start_receipt: RootSelectedDisplayStartReceipt | None) -> bool:
        if (type(start_receipt) is not RootSelectedDisplayStartReceipt
                or start_receipt._seal is None
                or start_receipt.selection != admission.selected_startup
                or self.monotonic() >= start_receipt.expires_monotonic):
            return False
        try:
            opened = self.xauthority_registry.resolve_selected(
                start_receipt.xauthority_receipt.receipt_handle,
                remote_enrollment_id=admission.remote_enrollment_id,
                native_profile_id=admission._display_startup.native_profile_id,
                native_generation=admission._display_startup.native_generation,
                display_profile_id=admission.role_bindings["display"].profile_id,
                display_generation=admission.role_bindings["display"].generation,
                display_name=admission._display_startup.display_name,
            )
            try:
                return (opened.receipt is start_receipt.xauthority_receipt
                        and opened.process_id == getattr(start_receipt.process_receipt, "process_id", None))
            finally:
                opened.close()
        except Exception:
            return False

    def control_selected_role(self, admission_handle: str, role: str, action: str, *,
                              timeout: float = 30.0,
                              cancelled: Callable[[], bool] | None = None,
                              _stop_reason: str = "shutdown") -> Any:
        """Issue a fresh typed status/stop effect for this root-retained launch."""
        cancelled = cancelled or (lambda: False)
        if action not in {"status", "stop"} or role not in _ROLES:
            raise SelectedStartupDenied("selected role control action is not fixed")
        admission = self.resolve_current_admission(admission_handle)
        binding = self.resolve_selected_recipe_binding(admission, role, action,
                                                       _stop_reason=_stop_reason)
        grant = self.issue_role_grant(admission_handle, role, action,
                                      _stop_reason=_stop_reason)
        verified = self.consume_role_grant(grant, admission_handle, role, action,
                                           _stop_reason=_stop_reason)
        proof = self.resolve_startup_controller_proof(
            admission.controller_proof_handle, admission_handle,
        )
        try:
            if cancelled() or not proof.is_current():
                raise SelectedStartupDenied("selected startup controller changed before control effect")
            binding = self.resolve_selected_recipe_binding(admission, role, action,
                                                            _stop_reason=_stop_reason)
            result = self.custody.perform_root_selected_service_effect(
                binding.service_profile, verified, startup_selection_payload(binding),
                timeout=min(float(timeout), admission.expires_monotonic - self.monotonic()),
                cancelled=cancelled, controller_proof=proof,
            )
            if action == "stop":
                with self._lock:
                    self._started_processes.pop((admission_handle, role), None)
            return result
        finally:
            proof.close()

    def _resolve_selection(self, remote_id: str, row: Any, network: Any) -> Any:
        from .native_display_startup import SelectedDisplayStartup

        if (getattr(row, "remote_enrollment_id", None) != remote_id
                or getattr(row, "network_enrollment_id", None) != getattr(network, "id", None)):
            raise SelectedStartupDenied("selected remote/network enrollment does not join")
        native_profile = getattr(row, "native_profile_id", None)
        native_generation = getattr(row, "native_generation", None)
        digest = self._service_generation_digest()
        binding = self.active_bindings.resolve_selected_native_principal(
            native_profile, native_generation, digest,
        )
        # Display-only security fields are projected from the selected
        # protected service role, never from the start caller.
        display_role = self._resolve_role_binding_from_row(row, "display")
        profile = display_role.service_profile
        display_name = getattr(row, "display_name", None)
        if not isinstance(display_name, str):
            raise SelectedStartupDenied("selected display name is not protected")
        return SelectedDisplayStartup(
            remote_enrollment_id=remote_id,
            native_profile_id=native_profile,
            native_generation=native_generation,
            display_profile_id=display_role.profile_id,
            display_generation=display_role.generation,
            display_name=display_name,
            receipt_handle=secrets.token_urlsafe(32),
            display_uid=display_role.subject_uid,
            display_gid=display_role.subject_gid,
            xauthority_reader_gid=getattr(row, "xauthority_reader_gid", None),
        )

    def _resolve_role_bindings(self, row: Any, _selection: Any,
                               service_digest: str) -> Mapping[str, RootSelectedStartupRoleBinding]:
        bindings = {
            role: self._resolve_role_binding_from_row(row, role)
            for role in _ROLES
        }
        for role, binding in bindings.items():
            principal = self.active_bindings.resolve_selected_native_principal(
                binding.profile_id, binding.generation, service_digest,
            )
            if (principal.principal_id != binding.principal_id
                    or principal.namespace_id != binding.namespace_identity
                    or principal.uid != binding.subject_uid):
                raise SelectedStartupDenied("selected role principal differs from its protected service row")
        return MappingProxyType(bindings)

    def _resolve_role_binding_from_row(self, row: Any,
                                       role: str) -> RootSelectedStartupRoleBinding:
        if role not in _ROLES:
            raise SelectedStartupDenied("selected startup role is not in the fixed set")
        prefix = role + "_"
        enrollment_id = getattr(row, prefix + "enrollment_id", None)
        generation = getattr(row, prefix + "generation", None)
        operation_id = getattr(row, prefix + "operation_id", None)
        operation = self.active_bindings.resolve_selected_operation(
            enrollment_id, generation, "process.start", operation_id,
        )
        profile = self.active_bindings.process_profiles.get(operation.profile_id)
        if (profile is None or profile.enrollment_id != enrollment_id
                or profile.generation != generation
                or profile.operation_targets.get("process.start") != operation.target):
            raise SelectedStartupDenied("selected role profile or process.start target is unavailable")
        recipe = profile.operation_recipes.get(operation_id)
        if not isinstance(recipe, Mapping):
            raise SelectedStartupDenied("selected startup recipe is not parameters-empty")
        parameter_schema_id = recipe.get("parameter_schema_id")
        schema = profile.parameter_schemas.get(parameter_schema_id)
        if (not isinstance(schema, Mapping)
                or schema.get("id") != parameter_schema_id
                or schema.get("fields") not in ((), [])):
            raise SelectedStartupDenied("selected startup recipe parameter schema is not empty")
        executable_id = recipe.get("executable_artifact_id")
        executable_sha = recipe.get("executable_sha256")
        children = recipe.get("child_artifact_refs")
        if (not isinstance(executable_id, str) or not _DIGEST.fullmatch(executable_sha or "")
                or not isinstance(children, Mapping)):
            raise SelectedStartupDenied("selected role recipe executable closure is malformed")
        closure = {
            "recipe": recipe,
            "executable_artifact_id": executable_id,
            "executable_sha256": executable_sha,
            "child_artifact_refs": dict(children),
        }
        closure_bytes = canonical_bytes(closure)
        closure_digest = hashlib.sha256(closure_bytes).hexdigest()
        principal = self.active_bindings.resolve_selected_native_principal(
            operation.profile_id, operation.generation,
            self._service_generation_digest(),
        )
        return RootSelectedStartupRoleBinding(
            role=role, action="start", service_enrollment_id=enrollment_id,
            profile_id=operation.profile_id, generation=generation,
            principal_id=operation.principal_id,
            namespace_identity=principal.namespace_id,
            subject_uid=operation.service_uid, subject_gid=operation.service_gid,
            operation_id=operation_id, operation="process.start",
            capability="hermes-profile-invoke", target=operation.target,
            recipe_sha256=hashlib.sha256(canonical_bytes(dict(recipe))).hexdigest(),
            source_closure_sha256=closure_digest,
            source_receipt_handles=tuple(getattr(row, role + "_source_receipt_handles", ())),
            service_profile=profile, process_operation=operation,
            source_closure=closure,
        )

    def _retained_process_id(self, admission: RootVerifiedStartupAdmission,
                             role: str) -> str:
        with self._lock:
            receipt = self._started_processes.get((admission.admission_handle, role))
        if receipt is None:
            raise SelectedStartupDenied("selected role has no root-retained managed start receipt")
        process_id = getattr(receipt, "process_id", None)
        generation = getattr(receipt, "generation", None)
        if (not isinstance(process_id, str) or not process_id
                or generation != admission.role_bindings[role].generation
                or self.monotonic() >= admission.expires_monotonic):
            raise SelectedStartupDenied("selected managed process receipt is stale")
        resolver = getattr(self.custody, "resolve_active_process_handle", None)
        if not callable(resolver):
            raise SelectedStartupDenied("root process receipt resolver is unavailable")
        try:
            lease = resolver(admission.role_bindings[role].profile_id,
                             admission.role_bindings[role].generation)
            try:
                if (getattr(lease, "process_id", None) != process_id
                        or getattr(lease, "generation", None) != generation
                        or not callable(getattr(lease, "is_current", None))
                        or not lease.is_current()):
                    raise SelectedStartupDenied("selected managed process is no longer current")
            finally:
                close = getattr(lease, "close", None)
                if callable(close):
                    close()
        except SelectedStartupDenied:
            raise
        except Exception:
            raise SelectedStartupDenied("selected managed process receipt is unavailable") from None
        return process_id

    def _role_binding_current(self, row: Any,
                              binding: RootSelectedStartupRoleBinding) -> bool:
        current = self._resolve_role_binding_from_row(row, binding.role)
        return current == binding

    def _network_row_current(self, row: Any,
                             bindings: Mapping[str, RootSelectedStartupRoleBinding]) -> bool:
        members = set(getattr(row, "member_enrollment_ids", ()))
        selected = {binding.service_enrollment_id for binding in bindings.values()}
        return members == selected and bool(getattr(row, "policy_artifact_id", ""))

    def _resolve_overlay_receipt(self, row: Any,
                                 admission: RootVerifiedStartupAdmission) -> Any:
        return self.overlay_registry.resolve_selected_patch(
            admission.selected_startup.patch_receipt_handle,
            admission.selected_startup,
        )

    def _selected_xauthority_binding(self, admission: RootVerifiedStartupAdmission,
                                     role: str) -> Any | None:
        from .native_display_startup import XauthorityMountBinding

        if role == "display":
            prepared = self._prepared_xauthority.get(admission.admission_handle)
            if prepared is None:
                raise SelectedStartupDenied("display Xauthority preparation is not retained")
            binding = admission._xauthority_registry.mount_binding(prepared)
            if (type(binding) is not XauthorityMountBinding
                    or not admission._xauthority_registry.verify_mount_binding(binding)):
                raise SelectedStartupDenied("display Xauthority mount binding is not current")
            return binding
        if role == "desktop":
            receipt = self._display_start_receipts.get(admission.admission_handle)
            if not self._display_receipt_current(admission, receipt):
                raise SelectedStartupDenied("Desktop requires the actual current display/Xauthority receipt")
            prepared = self._prepared_xauthority.get(admission.admission_handle)
            if prepared is None:
                raise SelectedStartupDenied("Desktop Xauthority source is not retained")
            binding = admission._xauthority_registry.mount_binding(prepared)
            if (type(binding) is not XauthorityMountBinding
                    or not admission._xauthority_registry.verify_mount_binding(binding)):
                raise SelectedStartupDenied("Desktop Xauthority mount binding is not current")
            return binding
        return None

    def _service_generation_digest(self) -> str:
        digest = getattr(self.active_bindings.enrollment_catalog, "digest", None)
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise SelectedStartupDenied("active root service generation digest is unavailable")
        return digest

    def _setup_controller_current(self, session: Any, intent: str,
                                  identity: Mapping[str, Any]) -> bool:
        try:
            return (self.setup_sessions.operation_intent(session) == intent
                    and self._controller_identity(os.getpid()) == identity)
        except Exception:
            return False

    @staticmethod
    def _pidfd_matches(pidfd: int, pid: int) -> bool:
        try:
            stat_path = f"/proc/self/fdinfo/{pidfd}"
            with open(stat_path, encoding="ascii") as stream:
                lines = stream.readlines()
            for line in lines:
                if line.startswith("Pid:"):
                    return int(line.split(":", 1)[1].strip()) == pid
        except (OSError, ValueError):
            return False
        return False

    @staticmethod
    def _controller_identity(pid: int) -> dict[str, Any]:
        proc = f"/proc/{pid}"
        stat_text = Path(f"{proc}/stat").read_text(encoding="ascii")
        start_ticks = int(stat_text[stat_text.rfind(")") + 2:].split()[19])
        status = Path(f"{proc}/status").read_text(encoding="ascii").splitlines()
        uid_line = next(line for line in status if line.startswith("Uid:"))
        uid = int(uid_line.split()[1])
        cgroup_identity = Path(f"{proc}/cgroup").read_text(encoding="ascii").strip().split(":", 2)[-1]
        if not cgroup_identity.startswith("/"):
            cgroup_identity = "/" + cgroup_identity
        return {
            "pid": pid, "uid": uid, "start_ticks": start_ticks,
            "cgroup_identity": cgroup_identity,
            "mount_namespace_inode": os.stat(f"{proc}/ns/mnt").st_ino,
            "network_namespace_inode": os.stat(f"{proc}/ns/net").st_ino,
        }


def sys_platform_linux() -> bool:
    import sys
    return sys.platform.startswith("linux")
