"""Root-owned functional health receipt observer for the selected Hermes run.

The resolver callables in this module are in-process root adapters. They must
select/launch an enrolled health operation, resolve event IDs from trusted
registries, and parse the reviewed result schema. This module deliberately has
no RPC method which accepts worker status, stdout, booleans, or event claims.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import select
import stat
import threading
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .types import AuthorityDenied, Sensitivity, canonical_bytes, canonical_digest

_EVENT_KINDS = frozenset({
    "loader-ready", "native-request", "provider-result", "tool-invocation",
    "tool-result", "terminal",
})
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HEALTH_OPERATION = "hermes-agent-health-v1"
_HEALTH_PARAMETER_SCHEMA = "no-caller-parameters-v1"


def _pidfd_exited(pidfd: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeHealthStartAdmission:
    """Sealed, short-lived authority to start one selected native health recipe.

    Public fields are the v159 binding. Private references are retained only in
    root memory and are rechecked by the owner before each use; none is a
    worker-supplied selector or a serialized proof.
    """

    schema: int
    admission_handle: str
    committed_enrollment_receipt_handle: str
    committed_enrollment_receipt_id: str
    bootstrap_transaction_handle: str
    enrollment_id: str
    profile_id: str
    principal_id: str
    process_generation: str
    service_generation_digest: str
    operation_id: str
    parameter_schema_id: str
    parameter_schema_sha256: str
    recipe_sha256: str
    health_fixture_artifact_id: str
    health_fixture_sha256: str
    health_fixture_receipt_handle: str
    health_result_schema_id: str
    health_result_schema_sha256: str
    native_package_id: str
    native_package_generation: str
    native_closure_sha256: str
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _instance_seal: object = field(repr=False, compare=False)
    _verified_commit: Any = field(repr=False, compare=False)
    _service_profile: Any = field(repr=False, compare=False)
    _process_operation: Any = field(repr=False, compare=False)
    _controller_lease: Any = field(repr=False, compare=False)
    _fixture_bytes: bytes = field(repr=False, compare=False)
    _source_binding: Any = field(repr=False, compare=False)
    _namespace_identity: str = field(repr=False, compare=False)
    authority_branch: str = "setup-local"
    _source_material: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        identifiers = (
            "admission_handle", "committed_enrollment_receipt_handle",
            "committed_enrollment_receipt_id", "bootstrap_transaction_handle",
            "enrollment_id", "profile_id", "principal_id", "process_generation",
            "operation_id", "parameter_schema_id", "health_fixture_artifact_id",
            "health_fixture_receipt_handle", "health_result_schema_id",
            "native_package_id", "native_package_generation", "controller_binding_handle",
        )
        if (type(self.schema) is not int or self.schema != 1
                or any(not _identifier(getattr(self, name)) for name in identifiers)
                or any(not _SHA256.fullmatch(getattr(self, name)) for name in (
                    "service_generation_digest", "parameter_schema_sha256", "recipe_sha256",
                    "health_fixture_sha256", "health_result_schema_sha256", "native_closure_sha256"))
                or self.operation_id != _HEALTH_OPERATION
                or self.parameter_schema_id != _HEALTH_PARAMETER_SCHEMA
                or not isinstance(self._fixture_bytes, bytes) or not self._fixture_bytes
                or hashlib.sha256(self._fixture_bytes).hexdigest() != self.health_fixture_sha256
                or self._instance_seal is None or self._verified_commit is None
                or self.authority_branch not in {"setup-local", "daemon-committed"}
                or self._service_profile is None or self._process_operation is None
                or self._source_binding is None or self._controller_lease is None
                or self.authority_branch == "daemon-committed" and self._source_material is None
                or not _identifier(self._namespace_identity)
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic
                or self.expires_monotonic - self.issued_monotonic > 30.0):
            raise AuthorityDenied("native.health.admission", "root selected health admission is malformed")

    def __repr__(self) -> str:
        return "RootNativeHealthStartAdmission(<root-private>)"

    @property
    def controller_proof_sha256(self) -> str:
        return self._controller_lease.proof_sha256

    @property
    def sensitivity(self) -> Sensitivity:
        return Sensitivity.PRIVATE

    @property
    def controller_proof_handle(self) -> str:
        return self.controller_binding_handle


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeHealthStartMaterial:
    """Strict result of the root committed-enrollment/source resolver.

    The resolver must return this exact type only after joining the active
    committed receipt, enrolled health recipe, source receipts, package closure,
    fixture bytes, result schema, and live root-controller proof.
    """

    verified_commit: Any = field(repr=False, compare=False)
    enrollment_id: str
    profile_id: str
    principal_id: str
    process_generation: str
    service_generation_digest: str
    parameter_schema_sha256: str
    recipe_sha256: str
    health_fixture_artifact_id: str
    health_fixture_sha256: str
    health_fixture_receipt_handle: str
    health_result_schema_id: str
    health_result_schema_sha256: str
    native_package_id: str
    native_package_generation: str
    native_closure_sha256: str
    controller_binding_handle: str
    service_profile: Any = field(repr=False, compare=False)
    process_operation: Any = field(repr=False, compare=False)
    controller_lease: Any = field(repr=False, compare=False)
    fixture_bytes: bytes = field(repr=False, compare=False)
    source_binding: Any = field(repr=False, compare=False)
    setup_plan: Any = field(repr=False, compare=False)
    namespace_identity: str

    def __post_init__(self) -> None:
        for name in ("enrollment_id", "profile_id", "principal_id", "process_generation",
                     "health_fixture_artifact_id", "health_fixture_receipt_handle",
                     "health_result_schema_id", "native_package_id", "native_package_generation",
                     "controller_binding_handle"):
            if not _identifier(getattr(self, name)):
                raise ValueError(f"health material {name} is invalid")
        if not _identifier(self.namespace_identity):
            raise ValueError("health material namespace identity is invalid")
        for name in ("service_generation_digest", "parameter_schema_sha256", "recipe_sha256",
                     "health_fixture_sha256", "health_result_schema_sha256", "native_closure_sha256"):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"health material {name} is invalid")
        if (not isinstance(self.fixture_bytes, bytes) or not self.fixture_bytes
                or hashlib.sha256(self.fixture_bytes).hexdigest() != self.health_fixture_sha256
                or self.verified_commit is None or self.service_profile is None
                or self.process_operation is None or self.controller_lease is None
                or self.source_binding is None or self.setup_plan is None):
            raise ValueError("health material lacks held root evidence")


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedHealthStartBinding:
    """The exact enrolled process.start binding signed for native health."""

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
    controller_proof_sha256: str
    service_profile: Any = field(repr=False, compare=False)
    process_operation: Any = field(repr=False, compare=False)
    source_closure: Any = field(repr=False, compare=False)
    recipient: str | None = None

    def __post_init__(self) -> None:
        if (self.role != "health" or self.action != "start"
                or self.operation != "process.start"
                or self.operation_id != _HEALTH_OPERATION
                or self.capability != "hermes-profile-invoke"
                or not all(_identifier(value) for value in (
                    self.service_enrollment_id, self.profile_id, self.generation,
                    self.principal_id, self.namespace_identity, self.target))
                or type(self.subject_uid) is not int or self.subject_uid <= 0
                or type(self.subject_gid) is not int or self.subject_gid < 0
                or not _SHA256.fullmatch(self.recipe_sha256)
                or not _SHA256.fullmatch(self.source_closure_sha256)
                or not _SHA256.fullmatch(self.controller_proof_sha256)
                or not isinstance(self.source_receipt_handles, tuple)
                or not self.source_receipt_handles
                or any(not _OPAQUE.fullmatch(item) for item in self.source_receipt_handles)
                or self.service_profile is None or self.process_operation is None
                or self.source_closure is None):
            raise AuthorityDenied("native.health.binding", "selected health start binding is malformed")

    def payload(self) -> bytes:
        return canonical_bytes({
            "schema": 1, "enrollment_id": self.service_enrollment_id,
            "generation": self.generation, "operation_id": self.operation_id,
            "parameters": {},
        })


@dataclass(frozen=True, slots=True, repr=False)
class _CommittedHealthEntry:
    handle: str
    receipt: Any = field(repr=False, compare=False)
    authorization: Any = field(repr=False, compare=False)
    verified_commit: Any = field(repr=False, compare=False)


class RootCommittedHealthEnrollmentRegistry:
    """Retain the exact committed transaction for the live post-activation call.

    A source resolver must independently join the health fixture, native package,
    operation recipe, result schema, and controller PIDFD. If that producer is
    absent, resolution fails closed; this registry never invents those records.
    """

    def __init__(self, *, setup_session_store: Any, source_material_resolver: Any,
                 root_journal: Any, monotonic: Callable[[], float] = time.monotonic):
        if (not callable(getattr(setup_session_store, "verify_committed_receipt", None))
                or not callable(getattr(source_material_resolver, "resolve_current_health_material", None))
                or not callable(getattr(source_material_resolver, "is_current", None))
                or not callable(monotonic) or root_journal is None):
            raise AuthorityDenied("native.health.registry", "committed health registry dependencies are incomplete")
        from .bootstrap_enrollment import RootSetupSessionStore
        if type(setup_session_store) is not RootSetupSessionStore:
            raise AuthorityDenied("native.health.registry", "health registry requires the root setup session store")
        self.setup_session_store = setup_session_store
        self.source_material_resolver = source_material_resolver
        self.root_journal = root_journal
        self.monotonic = monotonic
        self._entries: dict[str, _CommittedHealthEntry] = {}
        self._lock = threading.RLock()

    def retain_active_commit(self, receipt: Any, authorization: Any) -> str:
        """Called only at the live activation callpoint with exact typed proofs."""
        from .bootstrap_enrollment import EnrollmentReceipt, VerifiedRootSetupAuthorization
        if (type(receipt) is not EnrollmentReceipt or type(authorization) is not VerifiedRootSetupAuthorization
                or receipt.state != "committed"):
            raise AuthorityDenied("native.health.commit", "health requires the actual committed activation receipt")
        try:
            verified = self.setup_session_store.verify_committed_receipt(receipt, authorization)
        except Exception:
            raise AuthorityDenied("native.health.commit", "committed enrollment no longer verifies") from None
        from .bootstrap_enrollment import VerifiedCommittedEnrollment
        if (type(verified) is not VerifiedCommittedEnrollment
                or verified.receipt is not receipt
                or verified.receipt.transaction_handle != authorization.transaction_handle):
            raise AuthorityDenied("native.health.commit", "setup store returned a mismatched committed proof")
        handle = secrets.token_urlsafe(32)
        with self._lock:
            self._entries[handle] = _CommittedHealthEntry(handle, receipt, authorization, verified)
        return handle

    def resolve_current_health_material(self, handle: str, active_bindings: Any,
                                        verified_installer_release: Any,
                                        current_installed_actor_verifier: Any) -> RootNativeHealthStartMaterial:
        if not _OPAQUE.fullmatch(handle):
            raise AuthorityDenied("native.health.commit", "committed receipt handle is malformed")
        with self._lock:
            entry = self._entries.get(handle)
        if entry is None or entry.receipt.expires_monotonic <= self.monotonic():
            raise AuthorityDenied("native.health.commit", "committed receipt is not retained or has expired")
        try:
            verified = self.setup_session_store.verify_committed_receipt(
                entry.receipt, entry.authorization,
            )
            if (type(verified) is not type(entry.verified_commit)
                    or verified != entry.verified_commit):
                raise ValueError("committed transaction changed")
            material = self.source_material_resolver.resolve_current_health_material(
                verified, active_bindings, verified_installer_release,
                current_installed_actor_verifier,
            )
        except Exception:
            raise AuthorityDenied("native.health.sources", "current health fixture or native source closure is unavailable") from None
        if (type(material) is not RootNativeHealthStartMaterial
                or material.verified_commit is not entry.verified_commit):
            raise AuthorityDenied("native.health.sources", "health source resolver returned an untyped or unrelated binding")
        return material

    def resolve_current_health_material_for_receipt(
        self, receipt: Any, active_bindings: Any, verified_installer_release: Any,
        current_installed_actor_verifier: Any,
    ) -> RootNativeHealthStartMaterial:
        """Resolve only the exact committed receipt retained by this registry.

        The receipt is a lookup key, never authority: identity membership in
        this registry, the setup-store CAS, and the current source resolver are
        all rechecked before returning its held material.
        """
        from .bootstrap_enrollment import EnrollmentReceipt
        if type(receipt) is not EnrollmentReceipt:
            raise AuthorityDenied("native.health.commit", "health requires the retained enrollment receipt")
        with self._lock:
            matches = tuple(entry for entry in self._entries.values()
                            if entry.receipt is receipt)
        if len(matches) != 1 or receipt.expires_monotonic <= self.monotonic():
            raise AuthorityDenied("native.health.commit", "committed enrollment is not uniquely retained")
        entry = matches[0]
        try:
            verified = self.setup_session_store.verify_committed_receipt(
                entry.receipt, entry.authorization,
            )
            if type(verified) is not type(entry.verified_commit) or verified != entry.verified_commit:
                raise ValueError("committed transaction changed")
            material = self.source_material_resolver.resolve_current_health_material(
                verified, active_bindings, verified_installer_release,
                current_installed_actor_verifier,
            )
        except Exception:
            raise AuthorityDenied("native.health.sources", "current committed source material is unavailable") from None
        if (type(material) is not RootNativeHealthStartMaterial
                or material.verified_commit is not entry.verified_commit):
            raise AuthorityDenied("native.health.sources", "health source resolver returned unrelated material")
        return material

    def is_current_commit(self, commit: Any) -> bool:
        from .bootstrap_enrollment import VerifiedCommittedEnrollment
        if type(commit) is not VerifiedCommittedEnrollment:
            return False
        with self._lock:
            entries = tuple(self._entries.values())
        for entry in entries:
            if entry.verified_commit is commit:
                try:
                    return self.setup_session_store.verify_committed_receipt(
                        entry.receipt, entry.authorization,
                    ) == commit
                except Exception:
                    return False
        return False

    def is_current(self, admission: RootNativeHealthStartAdmission) -> bool:
        if type(admission) is not RootNativeHealthStartAdmission:
            return False
        with self._lock:
            entry = self._entries.get(admission.committed_enrollment_receipt_handle)
        if (entry is None or entry.verified_commit is not admission._verified_commit
                or admission.expires_monotonic <= self.monotonic()):
            return False
        try:
            verified = self.setup_session_store.verify_committed_receipt(
                entry.receipt, entry.authorization,
            )
            return bool(
                verified == entry.verified_commit
                and self.source_material_resolver.is_current(admission._source_binding)
                and admission._controller_lease.is_current()
            )
        except Exception:
            return False


_DAEMON_HEALTH_PROOF_SEAL = object()
_DAEMON_HEALTH_PROJECTION_SEAL = object()
_DAEMON_CONTROLLER_SEAL = object()
_DAEMON_HEALTH_TXN_ID = re.compile(r"[0-9a-f]{32}\Z")
_DAEMON_HEALTH_TXN_MAX = 256 * 1024


@dataclass(frozen=True, slots=True, repr=False)
class _RootDaemonCommittedHealthProjection:
    """Private, freshly re-resolved join of daemon intent and active root state."""

    transaction_row: Mapping[str, Any] = field(repr=False, compare=False)
    transaction_id: str
    current_generation_id: str
    current_generation_digest: str
    worker_runtime_record: Mapping[str, Any] = field(repr=False, compare=False)
    active_worker_row: Mapping[str, Any] = field(repr=False, compare=False)
    publication_receipt: Any = field(repr=False, compare=False)
    source_choice: Any = field(repr=False, compare=False)
    root_journal_selection: Any = field(repr=False, compare=False)
    intent_body: Mapping[str, Any] = field(repr=False, compare=False)
    controller_lease: Any = field(repr=False, compare=False)
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _DAEMON_HEALTH_PROJECTION_SEAL:
            raise TypeError("daemon health projections are issued by the current root registry")
        object.__setattr__(self, "transaction_row", MappingProxyType(dict(self.transaction_row)))
        object.__setattr__(self, "intent_body", MappingProxyType(dict(self.intent_body)))
        object.__setattr__(self, "worker_runtime_record", MappingProxyType(dict(self.worker_runtime_record)))
        object.__setattr__(self, "active_worker_row", MappingProxyType(dict(self.active_worker_row)))


@dataclass(frozen=True, slots=True, repr=False)
class RootDaemonCommittedHealthProof:
    """Short-lived daemon-owned proof for one actual committed transaction."""

    schema: int
    proof_handle: str
    intent_handle: str
    committed_transaction_id: str
    bootstrap_transaction_handle: str
    generation_id: str
    service_generation_digest: str
    publication_receipt_handle: str
    publication_sha256: str
    source_choice_selection_handle: str
    source_choice_signed_record_sha256: str
    health_definition_sha256: str
    expires_monotonic: float
    _registry: Any = field(repr=False, compare=False)
    _issuer_seal: object = field(repr=False, compare=False)
    _commit_projection: _RootDaemonCommittedHealthProjection = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        identifiers = ("proof_handle", "intent_handle", "committed_transaction_id",
                       "bootstrap_transaction_handle", "generation_id",
                       "publication_receipt_handle", "source_choice_selection_handle")
        digests = ("service_generation_digest", "publication_sha256",
                   "source_choice_signed_record_sha256", "health_definition_sha256")
        if (type(self.schema) is not int or self.schema != 1
                or any(not _identifier(getattr(self, name)) for name in identifiers)
                or any(not _SHA256.fullmatch(getattr(self, name)) for name in digests)
                or not math.isfinite(self.expires_monotonic)
                or self._issuer_seal is not _DAEMON_HEALTH_PROOF_SEAL
                or self._registry is None
                or type(self._commit_projection) is not _RootDaemonCommittedHealthProjection):
            raise AuthorityDenied("native.health.daemon_commit", "daemon committed-health proof is malformed")

    def __repr__(self) -> str:
        return "RootDaemonCommittedHealthProof(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootDaemonHealthControllerLease:
    """Distinct bounded lease for this installed daemon's fixed systemd MainPID."""

    proof_handle: str
    proof_sha256: str
    unit_id: str
    invocation_id: str
    pid: int
    uid: int
    gid: int
    start_ticks: int
    cgroup: str
    executable_sha256: str
    unit_file_sha256: str
    namespace_identity: str
    issued_monotonic: float
    expires_monotonic: float
    _pidfd: int = field(repr=False, compare=False)
    _runtime: Any = field(repr=False, compare=False)
    _receiver: Any = field(repr=False, compare=False)
    _active_receipt: Any = field(repr=False, compare=False)
    _release: Any = field(repr=False, compare=False)
    _actor: Any = field(repr=False, compare=False)
    _issuer_seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._issuer_seal is not _DAEMON_CONTROLLER_SEAL
                or not _OPAQUE.fullmatch(self.proof_handle)
                or not _SHA256.fullmatch(self.proof_sha256)
                or not _SHA256.fullmatch(self.executable_sha256)
                or not _SHA256.fullmatch(self.unit_file_sha256)
                or type(self.pid) is not int or self.pid <= 1
                or self.uid != 0 or self.gid != 0 or self._pidfd < 0
                or not self.unit_id or not self.invocation_id or not self.cgroup.startswith("/")
                or not _identifier(self.namespace_identity)
                or self.expires_monotonic <= self.issued_monotonic
                or self.expires_monotonic - self.issued_monotonic > 30.0):
            raise AuthorityDenied("native.health.daemon_controller", "daemon controller lease is malformed")

    @classmethod
    def from_root_runtime(cls, runtime: Any) -> "RootDaemonHealthControllerLease":
        from .runtime_composition import RootAuthorityRuntime
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        from .listener_activation import (RootActiveAuthorityListenerReceipt,
                                          RootAuthorityDaemonPeerObservation,
                                          RootAuthorityDaemonUnitSelection,
                                          RootAuthorityListenerActivationReceiver,
                                          RootCurrentAuthorityListenerObservation,
                                          RootSetupHealthIntentJournal)
        if (type(runtime) is not RootAuthorityRuntime or runtime.service.root_authority_runtime is not runtime
                or type(runtime.controller_release_receipt) is not VerifiedInstallerReleaseReceipt
                or type(runtime.controller_actor_observation) is not RootActorObservation):
            raise AuthorityDenied("native.health.daemon_controller", "installed daemon release and actor custody are unavailable")
        service = runtime.service
        receiver = getattr(service, "root_authority_listener_activation_receiver", None)
        journal = getattr(service, "root_setup_health_intent_journal", None)
        if (type(receiver) is not RootAuthorityListenerActivationReceiver
                or type(journal) is not RootSetupHealthIntentJournal
                or journal.receiver is not receiver
                or type(journal.active_receipt) is not RootActiveAuthorityListenerReceipt):
            raise AuthorityDenied("native.health.daemon_controller", "actual adopted daemon listener is unavailable")
        active_receipt = journal.active_receipt
        peer = None
        pidfd = -1
        try:
            observation = receiver.observe_active_current(active_receipt)
            if type(observation) is not RootCurrentAuthorityListenerObservation:
                raise ValueError("listener currentness observation is untyped")
            peer = receiver.inspector.inspect_authority_daemon(receiver.selection)
            actor = runtime.controller_actor_observation
            release = runtime.controller_release_receipt
            actor.verify_current(release)
            if (type(peer) is not RootAuthorityDaemonPeerObservation
                    or type(receiver.selection) is not RootAuthorityDaemonUnitSelection
                    or peer.pid != os.getpid() or peer.uid != 0 or peer.gid != 0
                    or peer.pid != active_receipt.daemon_pid
                    or peer.start_ticks != active_receipt.daemon_start_ticks
                    or peer.invocation_id != active_receipt.daemon_invocation_id
                    or peer.unit_id != active_receipt.daemon_unit_id
                    or actor.pid != peer.pid or actor.start_time != peer.start_ticks
                    or (peer.unit_id != receiver.selection.unit_id
                        or peer.fragment_sha256 != receiver.selection.unit_file_sha256
                        or peer.executable_sha256 != receiver.selection.interpreter_sha256)):
                raise ValueError("systemd MainPID differs from the actual root daemon actor")
            receiver.inspector.verify_current(peer, receiver.selection)
            actor.verify_current(release)
            pidfd = os.dup(peer.pidfd)
            namespace_identity = "daemon-ns-" + hashlib.sha256(
                canonical_bytes([list(item) for item in actor.namespace_inodes])).hexdigest()
            now = time.monotonic()
            expiry = min(now + 30.0, observation.expires_monotonic)
            if expiry <= now:
                raise ValueError("daemon currentness observation expired")
            proof_body = {
                "unit": peer.unit_id, "invocation": peer.invocation_id,
                "pid": peer.pid, "uid": peer.uid, "gid": peer.gid,
                "start_ticks": peer.start_ticks, "cgroup": peer.cgroup,
                "executable_sha256": peer.executable_sha256,
                "unit_file_sha256": peer.fragment_sha256,
                "release_deployment_receipt_sha256": release.deployment_receipt_sha256,
                "release_closure_manifest_sha256": release.closure_manifest_sha256,
                "actor_namespace_inodes": [list(item) for item in actor.namespace_inodes],
                "active_listener_record_sha256": observation.activation_record_sha256,
            }
            return cls(
                secrets.token_urlsafe(32), hashlib.sha256(canonical_bytes(proof_body)).hexdigest(),
                peer.unit_id, peer.invocation_id, peer.pid, peer.uid, peer.gid,
                peer.start_ticks, peer.cgroup, peer.executable_sha256, peer.fragment_sha256,
                namespace_identity, now, expiry, pidfd, runtime, receiver, active_receipt,
                release, actor, _DAEMON_CONTROLLER_SEAL,
            )
        except Exception:
            if pidfd >= 0:
                os.close(pidfd)
            raise AuthorityDenied("native.health.daemon_controller", "fixed daemon MainPID lease could not be verified") from None
        finally:
            if peer is not None:
                peer.close()

    def is_current(self) -> bool:
        if self._issuer_seal is not _DAEMON_CONTROLLER_SEAL or time.monotonic() >= self.expires_monotonic:
            return False
        try:
            from .listener_activation import RootAuthorityDaemonPeerObservation
            observation = self._receiver.observe_active_current(self._active_receipt)
            peer = self._receiver.inspector.inspect_authority_daemon(self._receiver.selection)
            try:
                self._actor.verify_current(self._release)
                self._receiver.inspector.verify_current(peer, self._receiver.selection)
                return bool(
                    type(peer) is RootAuthorityDaemonPeerObservation
                    and (peer.unit_id, peer.invocation_id, peer.pid, peer.uid, peer.gid,
                         peer.start_ticks, peer.cgroup, peer.executable_sha256,
                         peer.fragment_sha256)
                    == (self.unit_id, self.invocation_id, self.pid, self.uid, self.gid,
                        self.start_ticks, self.cgroup, self.executable_sha256,
                        self.unit_file_sha256)
                    and (observation.daemon_pid, observation.daemon_start_ticks,
                         observation.daemon_invocation_id)
                    == (self.pid, self.start_ticks, self.invocation_id)
                    and self._runtime.service.root_authority_runtime is self._runtime
                )
            finally:
                peer.close()
        except Exception:
            return False

    def close(self) -> None:
        try:
            os.close(self._pidfd)
        except OSError:
            pass

    @property
    def pidfd(self) -> int:
        return self._pidfd

    @property
    def process_uid(self) -> int:
        return self.uid

    @property
    def process_gid(self) -> int:
        return self.gid

    @property
    def cgroup_identity(self) -> str:
        return self.cgroup

    @property
    def mount_namespace_inode(self) -> int:
        return dict(self._actor.namespace_inodes)["mnt"]

    @property
    def network_namespace_inode(self) -> int:
        return dict(self._actor.namespace_inodes)["net"]


def _read_current_daemon_transaction(root_journal: Any, transaction_id: str) -> dict[str, Any]:
    """Read exactly one root-owned committed transaction through held directory FDs."""
    from hermes_installer.protected_enrollment import RootJournalSelection
    if (type(root_journal) is not RootJournalSelection
            or root_journal.root_id != "installer-authority-journal-v1"
            or not _DAEMON_HEALTH_TXN_ID.fullmatch(transaction_id)):
        raise AuthorityDenied("native.health.daemon_commit", "committed transaction selector is invalid")
    root_fd = transactions_fd = record_fd = -1
    try:
        root_fd = os.open(root_journal.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        root = os.fstat(root_fd)
        named = root_journal.path.lstat()
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or root.st_gid != 0
                or stat.S_IMODE(root.st_mode) != 0o700
                or (root.st_dev, root.st_ino) != (root_journal.device, root_journal.inode)
                or (named.st_dev, named.st_ino) != (root.st_dev, root.st_ino)):
            raise ValueError("selected journal root changed")
        transactions_fd = os.open("bootstrap-transactions", os.O_RDONLY | os.O_DIRECTORY |
                                   os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        directory = os.fstat(transactions_fd)
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
                or directory.st_gid != 0 or stat.S_IMODE(directory.st_mode) != 0o700):
            raise ValueError("transaction directory custody changed")
        filename = transaction_id + ".json"
        record_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=transactions_fd)
        before = os.fstat(record_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size <= 0 or before.st_size > _DAEMON_HEALTH_TXN_MAX):
            raise ValueError("transaction record custody is invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            part = os.read(record_fd, min(16384, _DAEMON_HEALTH_TXN_MAX + 1 - total))
            if not part:
                break
            total += len(part)
            if total > _DAEMON_HEALTH_TXN_MAX:
                raise ValueError("transaction record exceeded its read bound")
            chunks.append(part)
        after = os.fstat(record_fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or total != before.st_size):
            raise ValueError("transaction record changed while being read")
        raw = b"".join(chunks)
        row = json.loads(raw, object_pairs_hook=_unique_json_object,
                         parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite")))
        if not isinstance(row, dict) or canonical_bytes(row) != raw:
            raise ValueError("transaction record is not canonical")
        return row
    except AuthorityDenied:
        raise
    except Exception:
        raise AuthorityDenied("native.health.daemon_commit", "current committed transaction is unavailable") from None
    finally:
        for fd in (record_fd, transactions_fd, root_fd):
            if fd >= 0:
                os.close(fd)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


class RootDaemonCommittedHealthEnrollmentRegistry:
    """Resolve daemon health proofs from current committed root state, not setup memory."""

    def __init__(self, runtime: Any, root_journal: Any, release: Any, actor: Any,
                 monotonic: Callable[[], float] = time.monotonic):
        from .runtime_composition import RootAuthorityRuntime
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        from .root_setup_choices import RootSetupChoiceRegistry
        from hermes_installer.protected_enrollment import RootJournalSelection
        if (type(runtime) is not RootAuthorityRuntime or runtime.service.root_authority_runtime is not runtime
                or type(root_journal) is not RootJournalSelection
                or root_journal.root_id != "installer-authority-journal-v1"
                or root_journal.service_generation_digest != runtime.enrollment.protected_enrollment_digest
                or type(release) is not VerifiedInstallerReleaseReceipt
                or type(actor) is not RootActorObservation
                or type(runtime.root_setup_choice_registry) is not RootSetupChoiceRegistry
                or runtime.root_setup_choice_registry.service is not runtime.service
                or not callable(monotonic) or os.name != "posix" or os.geteuid() != 0):
            raise AuthorityDenied("native.health.daemon_registry", "current installed daemon root owners are required")
        self.runtime, self.root_journal = runtime, root_journal
        self.release, self.actor, self.monotonic = release, actor, monotonic
        self.choice_registry = runtime.root_setup_choice_registry
        self._issuer_seal = _DAEMON_HEALTH_PROOF_SEAL
        self._proofs: dict[str, RootDaemonCommittedHealthProof] = {}
        self._lock = threading.RLock()
        self.actor.verify_current(self.release)
        self._verify_root_journal_current()

    @classmethod
    def from_root_runtime(cls, runtime: Any) -> "RootDaemonCommittedHealthEnrollmentRegistry":
        from .runtime_composition import RootAuthorityRuntime, _AUTHORITY_JOURNAL_ROOT_ID
        if type(runtime) is not RootAuthorityRuntime:
            raise AuthorityDenied("native.health.daemon_registry", "exact current root runtime is required")
        digest = runtime.enrollment.protected_enrollment_digest
        try:
            root_journal = runtime.resolve_root_journal(
                _AUTHORITY_JOURNAL_ROOT_ID, expected_active_generation_digest=digest)
        except Exception:
            raise AuthorityDenied("native.health.daemon_registry", "active protected root journal is unavailable") from None
        return cls(runtime, root_journal, runtime.controller_release_receipt,
                   runtime.controller_actor_observation)

    def _verify_root_journal_current(self) -> None:
        runtime = self.runtime
        digest = runtime.enrollment.protected_enrollment_digest
        if (digest != runtime.bindings.service_generation_digest
                or digest != self.root_journal.service_generation_digest):
            raise AuthorityDenied("native.health.daemon_current", "protected daemon generation changed")
        try:
            current = runtime.resolve_root_journal(
                self.root_journal.root_id, expected_active_generation_digest=digest)
            self.release.verify_current()
            self.actor.verify_current(self.release)
        except Exception:
            raise AuthorityDenied("native.health.daemon_current", "installed daemon or root journal is stale") from None
        if current != self.root_journal:
            raise AuthorityDenied("native.health.daemon_current", "active root journal selection changed")

    def _resolve_current_projection(self, intent_handle: str) -> _RootDaemonCommittedHealthProjection:
        from .listener_activation import RootAcceptedHealthIntent, RootSetupHealthIntentJournal
        from .setup_policy_publication import PolicyPublicationReceiptResolver, RootSetupPublicationReceipt
        from .root_setup_choices import RootAdoptedSetupChoiceSelection
        if not _OPAQUE.fullmatch(intent_handle):
            raise AuthorityDenied("native.health.daemon_intent", "health intent handle is malformed")
        service = self.runtime.service
        receiver = getattr(service, "root_authority_listener_activation_receiver", None)
        journal = getattr(service, "root_setup_health_intent_journal", None)
        if (receiver is None or type(journal) is not RootSetupHealthIntentJournal
                or journal.root_journal != self.root_journal or journal.receiver is not receiver
                or journal.active_receipt is None):
            raise AuthorityDenied("native.health.daemon_intent", "daemon-owned accepted health journal is unavailable")
        try:
            observation = receiver.observe_active_current(journal.active_receipt)
            accepted = journal.resolve_current_accepted_intent_for_handle(
                intent_handle, receiver, journal.active_receipt)
            publication = PolicyPublicationReceiptResolver.resolve_current()
        except Exception:
            raise AuthorityDenied("native.health.daemon_intent", "accepted intent, listener, or publication is stale") from None
        if type(accepted) is not RootAcceptedHealthIntent or accepted._journal is not journal:
            raise AuthorityDenied("native.health.daemon_intent", "health intent lacks daemon journal provenance")
        body = dict(accepted.body)
        required = {
            "schema", "purpose", "intent_handle", "nonce_sha256", "setup_actor_witness_handle",
            "setup_actor_witness_sha256", "activation_id", "daemon_unit_id", "daemon_invocation_id",
            "committed_transaction_id", "bootstrap_transaction_handle", "generation_id",
            "service_generation_digest", "publication_receipt_handle", "publication_sha256",
            "profile_id", "enrollment_id", "source_choice_selection_handle",
            "source_choice_signed_record_sha256", "source_choice_epoch", "source_choice_revocation_epoch",
            "health_definition_sha256", "issued_monotonic", "expires_monotonic",
        }
        if (set(body) != required or body.get("schema") != 1
                or body.get("purpose") != "root-native-health-intent-v1"
                or body.get("intent_handle") != intent_handle
                or body.get("daemon_unit_id") != observation.daemon_unit_id
                or body.get("daemon_invocation_id") != observation.daemon_invocation_id
                or body.get("service_generation_digest") != self.runtime.enrollment.protected_enrollment_digest
                or body.get("publication_receipt_handle") != observation.publication_receipt_handle
                or body.get("publication_sha256") != observation.publication_sha256
                or body.get("generation_id") is None
                or body.get("expires_monotonic", 0) <= self.monotonic()
                or body.get("expires_monotonic", 0) - body.get("issued_monotonic", 0) > 30.0):
            raise AuthorityDenied("native.health.daemon_intent", "accepted intent is not the exact current bounded request")
        self._verify_root_journal_current()
        row = _read_current_daemon_transaction(self.root_journal, body["committed_transaction_id"])
        setup = row.get("setup_authorization")
        if (row.get("schema") != 1 or row.get("transaction_id") != body["committed_transaction_id"]
                or row.get("state") != "committed"
                or row.get("generation_digest") != body["service_generation_digest"]
                or row.get("previous_generation_digest") != (setup.get("expected_previous_generation_digest")
                                                               if isinstance(setup, dict) else None)
                or row.get("provision_receipt_handle") is None
                or not isinstance(setup, dict)
                or setup.get("transaction_handle") != body["bootstrap_transaction_handle"]
                or setup.get("operation_target_id") != "service-generation:bootstrap:install"):
            raise AuthorityDenied("native.health.daemon_commit", "setup transaction row is not the current committed health transaction")
        digest = self.runtime.enrollment.protected_enrollment_digest
        if (type(publication) is not RootSetupPublicationReceipt
                or publication.state != "active-committed"
                or publication.service_generation_digest != digest
                or publication.receipt_handle != body["publication_receipt_handle"]
                or publication.publication_sha256 != body["publication_sha256"]):
            raise AuthorityDenied("native.health.daemon_publication", "current publication differs from accepted intent")
        try:
            choice = self.choice_registry.resolve_current_adopted_choice_snapshot(
                body["source_choice_selection_handle"], "native-policy-preparation")
        except Exception:
            raise AuthorityDenied("native.health.daemon_source", "signed source choice is revoked or stale") from None
        if (type(choice) is not RootAdoptedSetupChoiceSelection
                or choice.selection_handle != body["source_choice_selection_handle"]
                or choice.signed_record_sha256 != body["source_choice_signed_record_sha256"]
                or choice.choice_epoch != body["source_choice_epoch"]
                or choice.revocation_epoch != body["source_choice_revocation_epoch"]
                or choice.service_generation_digest != digest
                or choice.active_publication_receipt_handle != publication.receipt_handle):
            raise AuthorityDenied("native.health.daemon_source", "signed source-choice join differs from the intent")
        rows = self.runtime.enrollment.native_worker_runtime_records
        current_rows = [candidate for candidate in rows
                        if isinstance(candidate, Mapping)
                        and candidate.get("source_choice_selection_handle") == choice.selection_handle]
        runtime_row = current_rows[0] if len(current_rows) == 1 else None
        active_rows = [candidate for candidate in self.runtime.enrollment.active_network_generation_records
                       if isinstance(candidate, Mapping) and runtime_row is not None
                       and candidate.get("worker_runtime_record_id") == runtime_row.get("id")]
        active_row = active_rows[0] if len(active_rows) == 1 else None
        if (runtime_row is None or active_row is None
                or runtime_row.get("generation_id") != body["generation_id"]
                or runtime_row.get("service_enrollment_id") != body["enrollment_id"]
                or runtime_row.get("profile_id") != body["profile_id"]
                or active_row.get("source_choice_signed_record_sha256")
                   != body["source_choice_signed_record_sha256"]
                or active_row.get("source_choice_epoch") != body["source_choice_epoch"]
                or active_row.get("source_choice_revocation_epoch") != body["source_choice_revocation_epoch"]
                or active_row.get("generation_id") != body["generation_id"]):
            raise AuthorityDenied("native.health.daemon_source", "active protected worker row differs from selected health source")
        controller = RootDaemonHealthControllerLease.from_root_runtime(self.runtime)
        now = self.monotonic()
        expiry = min(float(body["expires_monotonic"]), now + 30.0,
                     float(choice.expires_monotonic), controller.expires_monotonic)
        if expiry <= now:
            controller.close()
            raise AuthorityDenied("native.health.daemon_expired", "daemon health authority lease expired")
        projection = _RootDaemonCommittedHealthProjection(
            MappingProxyType(dict(row)), body["committed_transaction_id"], body["generation_id"],
            digest, MappingProxyType(dict(runtime_row)), MappingProxyType(dict(active_row)),
            publication, choice, self.root_journal, MappingProxyType(body),
            controller, expiry, _DAEMON_HEALTH_PROJECTION_SEAL,
        )
        return projection

    def resolve_current_commit(self, intent_handle: str) -> RootDaemonCommittedHealthProof:
        projection = self._resolve_current_projection(intent_handle)
        body = projection.intent_body
        proof = RootDaemonCommittedHealthProof(
            1, secrets.token_urlsafe(32), intent_handle, projection.transaction_id,
            body["bootstrap_transaction_handle"], projection.current_generation_id,
            projection.current_generation_digest,
            projection.publication_receipt.receipt_handle,
            projection.publication_receipt.publication_sha256,
            projection.source_choice.selection_handle,
            projection.source_choice.signed_record_sha256,
            body["health_definition_sha256"], projection.expires_monotonic, self,
            self._issuer_seal, projection,
        )
        with self._lock:
            self._proofs[proof.proof_handle] = proof
        return proof

    def resolve_health_source_projection(
            self, proof: RootDaemonCommittedHealthProof) -> _RootDaemonCommittedHealthProjection:
        if (type(proof) is not RootDaemonCommittedHealthProof or proof._registry is not self
                or proof._issuer_seal is not self._issuer_seal
                or proof.expires_monotonic <= self.monotonic()):
            raise AuthorityDenied("native.health.daemon_proof", "daemon health proof is not current registry authority")
        with self._lock:
            if self._proofs.get(proof.proof_handle) is not proof:
                raise AuthorityDenied("native.health.daemon_proof", "daemon health proof was copied or revoked")
        current = self._resolve_current_projection(proof.intent_handle)
        try:
            if (current.transaction_id != proof.committed_transaction_id
                    or current.current_generation_id != proof.generation_id
                    or current.current_generation_digest != proof.service_generation_digest
                    or current.publication_receipt.publication_sha256 != proof.publication_sha256
                    or current.source_choice.signed_record_sha256 != proof.source_choice_signed_record_sha256
                    or current.intent_body["health_definition_sha256"] != proof.health_definition_sha256
                    or dict(current.transaction_row) != dict(proof._commit_projection.transaction_row)
                    or dict(current.worker_runtime_record) != dict(proof._commit_projection.worker_runtime_record)
                    or dict(current.active_worker_row) != dict(proof._commit_projection.active_worker_row)
                    or dict(current.intent_body) != dict(proof._commit_projection.intent_body)
                    or current.publication_receipt != proof._commit_projection.publication_receipt
                    or current.source_choice != proof._commit_projection.source_choice
                    or not proof._commit_projection.controller_lease.is_current()):
                raise AuthorityDenied("native.health.daemon_proof", "committed daemon health projection changed")
        except BaseException:
            current.controller_lease.close()
            raise
        current.controller_lease.close()
        # Return the already retained object only after independently rebuilding
        # the full projection; never return caller-copied projection fields.
        with self._lock:
            retained = self._proofs.get(proof.proof_handle)
        if retained is not proof or retained._commit_projection is None:
            raise AuthorityDenied("native.health.daemon_proof", "daemon health projection is no longer retained")
        return retained._commit_projection

    def is_current_commit(self, proof: Any) -> bool:
        if type(proof) is not RootDaemonCommittedHealthProof:
            return False
        try:
            self.resolve_health_source_projection(proof)
            return proof.expires_monotonic > self.monotonic()
        except Exception:
            return False


class RootNativeHealthStartAuthority:
    """One-use root issuer for a selected, committed native health operation.

    The committed-enrollment registry is an in-process root collaborator. Its
    required methods are ``resolve_current_health_material(handle, bindings,
    release, actor_verifier)`` and ``is_current(admission)``. Missing or
    untyped evidence is denied; this class does not mint fixture or package
    facts itself.
    """

    def __init__(self, *, active_bindings: Any, committed_enrollment_registry: Any,
                 verified_installer_release: Any, current_installed_actor_verifier: Any,
                 authority_service: Any, managed_process_custody: Any,
                 health_observer: Any, root_journal: Any,
                 monotonic: Callable[[], float] = time.monotonic,
                 daemon_material_registry: Any = None,
                 daemon_runtime: Any = None):
        daemon_registry_type = globals().get("RootDaemonCommittedHealthEnrollmentRegistry")
        daemon_mode = (daemon_registry_type is not None
                       and type(committed_enrollment_registry) is daemon_registry_type)
        required = (
            (verified_installer_release, "verify_current"),
            (authority_service, "issue_root_selected_service_effect"),
            (authority_service, "consume_root_selected_service_effect"),
            (managed_process_custody, "start_selected_health_operation"),
            (health_observer, "begin_selected_health"),
        )
        if daemon_mode:
            required += ((committed_enrollment_registry, "resolve_current_commit"),
                         (committed_enrollment_registry, "is_current_commit"),
                         (daemon_material_registry, "resolve_current_health_material"),
                         (daemon_material_registry, "is_current"),
                         (daemon_runtime, "resolve_root_journal"))
        else:
            required += ((committed_enrollment_registry, "resolve_current_health_material"),
                         (committed_enrollment_registry, "is_current"),
                         (current_installed_actor_verifier, "verify_current"))
        if active_bindings is None or root_journal is None or not callable(monotonic) or any(
                not callable(getattr(owner, method, None)) for owner, method in required):
            raise AuthorityDenied("native.health.start.attach", "health start root dependencies are incomplete")
        if daemon_mode and (getattr(daemon_runtime, "service", None) is not authority_service
                            or daemon_runtime.bindings is not active_bindings
                            or daemon_runtime.process_manager is not managed_process_custody
                            or daemon_material_registry.commit_registry is not committed_enrollment_registry
                            or daemon_runtime.service.root_authority_runtime is not daemon_runtime):
            raise AuthorityDenied("native.health.start.attach", "daemon health owners do not share the exact current runtime")
        self.active_bindings = active_bindings
        self.committed_enrollment_registry = committed_enrollment_registry
        self.daemon_material_registry = daemon_material_registry
        self.daemon_runtime = daemon_runtime
        self.daemon_mode = daemon_mode
        self.verified_installer_release = verified_installer_release
        self.current_installed_actor_verifier = current_installed_actor_verifier
        self.authority_service = authority_service
        self.managed_process_custody = managed_process_custody
        self.health_observer = health_observer
        self.root_journal = root_journal
        self.monotonic = monotonic
        self._seal = object()
        self._admissions: dict[str, RootNativeHealthStartAdmission] = {}
        self._started: dict[str, Any] = {}
        self._daemon_materials: dict[str, Any] = {}
        self._daemon_intents: dict[str, tuple[str, str]] = {}
        self.daemon_run_registry: Any = None
        self._used: set[str] = set()
        self._lock = threading.RLock()

    @classmethod
    def from_root_daemon_runtime(cls, runtime: Any, commit_registry: Any,
                                 material_registry: Any, run_registry: Any
                                 ) -> "RootNativeHealthStartAuthority":
        from .runtime_composition import RootAuthorityRuntime
        from .listener_activation import RootSetupHealthIntentJournal
        if (type(runtime) is not RootAuthorityRuntime or runtime.service.root_authority_runtime is not runtime
                or getattr(runtime.service, "root_setup_health_intent_journal", None) is None
                or type(runtime.service.root_setup_health_intent_journal) is not RootSetupHealthIntentJournal
                or getattr(run_registry, "observer", None) is None
                or getattr(run_registry, "material_registry", None) is not material_registry):
            raise AuthorityDenied("native.health.start.attach", "current daemon source/run owners are unavailable")
        authority = cls(
            active_bindings=runtime.bindings,
            committed_enrollment_registry=commit_registry,
            verified_installer_release=runtime.controller_release_receipt,
            current_installed_actor_verifier=runtime.controller_actor_observation,
            authority_service=runtime.service,
            managed_process_custody=runtime.process_manager,
            health_observer=run_registry.observer,
            root_journal=commit_registry.root_journal,
            daemon_material_registry=material_registry,
            daemon_runtime=runtime,
        )
        runtime.process_manager.bind_native_health_start_authority(authority)
        run_registry.bind_start_authority(authority)
        authority.daemon_run_registry = run_registry
        return authority

    def admit_daemon_selected_health(self, intent_handle: str) -> RootNativeHealthStartAdmission:
        """Turn one accepted journal intent into the exact daemon-tagged admission."""
        if not self.daemon_mode or not _OPAQUE.fullmatch(intent_handle):
            raise AuthorityDenied("native.health.daemon_intent", "current accepted daemon health intent is required")
        service = self.daemon_runtime.service
        from .listener_activation import RootAcceptedHealthIntent, RootSetupHealthIntentJournal
        journal = getattr(service, "root_setup_health_intent_journal", None)
        receiver = getattr(service, "root_authority_listener_activation_receiver", None)
        if type(journal) is not RootSetupHealthIntentJournal or receiver is not journal.receiver:
            raise AuthorityDenied("native.health.daemon_intent", "daemon-owned health intent journal is unavailable")
        try:
            retained = self.resolve_current_daemon_health_admission_for_intent(intent_handle)
        except AuthorityDenied:
            retained = None
        if retained is not None:
            return retained
        try:
            active_receipt = receiver.current_active_receipt()
            state_resolver = getattr(journal, "resolve_current_intent_state", None)
            if not callable(state_resolver) or state_resolver(intent_handle) != "accepted":
                raise ValueError
            accepted = journal.resolve_current_accepted_intent_for_handle(
                intent_handle, receiver, active_receipt,
            )
            if type(accepted) is not RootAcceptedHealthIntent or accepted._journal is not journal:
                raise ValueError
            proof = self.committed_enrollment_registry.resolve_current_commit(intent_handle)
            material = self.daemon_material_registry.resolve_current_health_material(proof)
            from .native_health_daemon import RootDaemonNativeHealthStartMaterial
            if (type(material) is not RootDaemonNativeHealthStartMaterial
                    or material._commit_proof is not proof
                    or material._controller_lease is not proof._commit_projection.controller_lease
                    or self.daemon_material_registry.is_current(material) is not True):
                raise ValueError
            projection = self.committed_enrollment_registry.resolve_health_source_projection(proof)
            if (projection.intent_body.get("intent_handle") != intent_handle
                    or projection.intent_body.get("health_definition_sha256") != material.health_definition_sha256
                    or material.committed_transaction_id != proof.committed_transaction_id
                    or material.bootstrap_transaction_handle != proof.bootstrap_transaction_handle
                    or material.generation_id != proof.generation_id
                    or material.service_generation_digest != proof.service_generation_digest
                    or material.publication_receipt_handle != proof.publication_receipt_handle
                    or material.publication_sha256 != proof.publication_sha256
                    or material.source_choice_signed_record_sha256 != proof.source_choice_signed_record_sha256):
                raise ValueError
            profile = material._service_profile
            operation = material._process_operation
            controller = material._controller_lease
            manager = self.managed_process_custody
            if (type(controller) is not RootDaemonHealthControllerLease
                    or controller is not proof._commit_projection.controller_lease
                    or not controller.is_current()
                    or manager.profiles.get(material.profile_id) is not profile
                    or profile.profile_id != material.profile_id
                    or profile.enrollment_id != material.enrollment_id
                    or profile.generation != material.process_generation
                    or profile.service_generation_digest != material.service_generation_digest
                    or operation.profile_id != profile.profile_id
                    or operation.generation != profile.generation
                    or operation.enrollment_id != profile.enrollment_id
                    or operation.operation_id != material.operation_id
                    or operation.principal_id != material.principal_id
                    or profile.principal_id != material.principal_id
                    or profile.namespace_identity != material.namespace_identity):
                raise ValueError
            recipe = (profile.operation_recipes or {}).get(material.operation_id)
            schema = (profile.parameter_schemas or {}).get(_HEALTH_PARAMETER_SCHEMA)
            if (not isinstance(recipe, Mapping) or not isinstance(schema, Mapping)
                    or schema.get("fields") not in ((), [])
                    or recipe.get("parameter_schema_id") != _HEALTH_PARAMETER_SCHEMA
                    or hashlib.sha256(canonical_bytes(dict(recipe))).hexdigest()
                       != material.process_recipe_sha256
                    or hashlib.sha256(canonical_bytes(dict(schema))).hexdigest()
                       != material.parameter_schema_sha256):
                raise ValueError
            source_binding = material._source_binding
            source_digest = getattr(source_binding, "native_closure_sha256", None)
            source_handles = getattr(source_binding, "source_member_receipt_handles", None)
            if (not _SHA256.fullmatch(source_digest or "")
                    or not isinstance(source_handles, tuple) or not source_handles
                    or any(not _OPAQUE.fullmatch(handle) for handle in source_handles)
                    or material.controller_binding_handle != controller.proof_handle):
                raise ValueError
            now = self.monotonic()
            expiry = min(now + 30.0, accepted.body["expires_monotonic"],
                         proof.expires_monotonic, material.expires_monotonic,
                         controller.expires_monotonic)
            if expiry <= now:
                raise ValueError
            handle = secrets.token_urlsafe(32)
            admission = RootNativeHealthStartAdmission(
                schema=1, admission_handle=handle,
                committed_enrollment_receipt_handle=intent_handle,
                committed_enrollment_receipt_id=proof.committed_transaction_id,
                bootstrap_transaction_handle=proof.bootstrap_transaction_handle,
                enrollment_id=material.enrollment_id, profile_id=material.profile_id,
                principal_id=material.principal_id, process_generation=material.process_generation,
                service_generation_digest=proof.service_generation_digest,
                operation_id=material.operation_id,
                parameter_schema_id=_HEALTH_PARAMETER_SCHEMA,
                parameter_schema_sha256=material.parameter_schema_sha256,
                recipe_sha256=material.process_recipe_sha256,
                health_fixture_artifact_id=material.health_fixture_artifact_id,
                health_fixture_sha256=material.health_fixture_sha256,
                health_fixture_receipt_handle=material.health_fixture_receipt_handle,
                health_result_schema_id=material.health_result_schema_id,
                health_result_schema_sha256=material.health_result_schema_sha256,
                native_package_id=material.native_package_id,
                native_package_generation=material.native_package_generation,
                native_closure_sha256=material.native_closure_sha256,
                controller_binding_handle=controller.proof_handle,
                issued_monotonic=now, expires_monotonic=expiry,
                _instance_seal=self._seal, _verified_commit=proof,
                _service_profile=profile, _process_operation=operation,
                _controller_lease=controller,
                _fixture_bytes=material._fixture_bytes, _source_binding=source_binding,
                _namespace_identity=material.namespace_identity,
                authority_branch="daemon-committed", _source_material=material,
            )
            # Marking started is the durable one-use barrier before any process effect.
            journal.mark_started(accepted)
            with self._lock:
                if handle in self._admissions:
                    raise ValueError("admission handle collision")
                self._admissions[handle] = admission
                self._daemon_materials[handle] = material
                self._daemon_intents[handle] = (intent_handle, accepted.intent_sha256)
            return admission
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("native.health.daemon_admission", "current daemon health source could not be admitted") from None

    @classmethod
    def from_root_runtime(cls, active_bindings: Any, committed_enrollment_registry: Any,
                          verified_installer_release: Any, current_installed_actor_verifier: Any,
                          authority_service: Any, managed_process_custody: Any,
                          health_observer: Any, root_journal: Any) -> "RootNativeHealthStartAuthority":
        return cls(
            active_bindings=active_bindings,
            committed_enrollment_registry=committed_enrollment_registry,
            verified_installer_release=verified_installer_release,
            current_installed_actor_verifier=current_installed_actor_verifier,
            authority_service=authority_service,
            managed_process_custody=managed_process_custody,
            health_observer=health_observer, root_journal=root_journal,
        )

    def admit_selected_health(self, committed_enrollment_receipt_handle: str) -> str:
        if self.daemon_mode or not _OPAQUE.fullmatch(committed_enrollment_receipt_handle):
            raise AuthorityDenied("native.health.admission", "committed receipt handle is malformed")
        try:
            material = self.committed_enrollment_registry.resolve_current_health_material(
                committed_enrollment_receipt_handle, self.active_bindings,
                self.verified_installer_release, self.current_installed_actor_verifier,
            )
        except Exception:
            raise AuthorityDenied("native.health.admission", "current committed health source is unavailable") from None
        if type(material) is not RootNativeHealthStartMaterial:
            raise AuthorityDenied("native.health.admission", "committed health resolver returned an untyped source")
        from .bootstrap_enrollment import VerifiedCommittedEnrollment
        from .selected_startup_authority import RootControllerProcessIdentityLease
        commit = material.verified_commit
        receipt = getattr(commit, "receipt", None)
        if (type(commit) is not VerifiedCommittedEnrollment or receipt is None
                or receipt.state != "committed"
                or receipt.generation_digest != material.service_generation_digest
                or material.service_generation_digest != getattr(self.active_bindings, "service_generation_digest", None)
                or type(material.controller_lease) is not RootControllerProcessIdentityLease
                or material.controller_lease.proof_handle != material.controller_binding_handle
                or not material.controller_lease.is_current()
                or not self.committed_enrollment_registry.is_current_commit(commit)):
            raise AuthorityDenied("native.health.admission", "commit or root controller proof is not current")
        self.verified_installer_release.verify_current()
        actor = self.current_installed_actor_verifier.verify_current(material.setup_plan)
        if not isinstance(actor, Mapping) or not actor:
            raise AuthorityDenied("native.health.actor", "installed root setup actor is not current")
        profile = material.service_profile
        operation = material.process_operation
        recipe = getattr(profile, "operation_recipes", {}).get(_HEALTH_OPERATION)
        schema = getattr(profile, "parameter_schemas", {}).get(_HEALTH_PARAMETER_SCHEMA)
        target = getattr(profile, "operation_targets", {}).get("process.start")
        if (getattr(operation, "operation_id", None) != _HEALTH_OPERATION
                or getattr(operation, "operation", None) != "process.start"
                or getattr(operation, "target", None) != target
                or getattr(operation, "enrollment_id", None) != material.enrollment_id
                or getattr(operation, "generation", None) != material.process_generation
                or getattr(operation, "profile_id", None) != material.profile_id
                or not isinstance(recipe, Mapping)
                or recipe.get("parameter_schema_id") != _HEALTH_PARAMETER_SCHEMA
                or not isinstance(schema, Mapping) or schema.get("fields") not in ((), [])
                or hashlib.sha256(canonical_bytes(dict(recipe))).hexdigest() != material.recipe_sha256
                or hashlib.sha256(canonical_bytes(dict(schema))).hexdigest() != material.parameter_schema_sha256
                or getattr(profile, "enrollment_id", None) != material.enrollment_id
                or getattr(profile, "generation", None) != material.process_generation
                or getattr(profile, "profile_id", None) != material.profile_id
                or getattr(operation, "principal_id", None) != material.principal_id):
            raise AuthorityDenied("native.health.recipe", "selected health recipe is not the fixed empty-parameter recipe")
        try:
            principal = self.active_bindings.resolve_selected_native_principal(
                material.profile_id, material.process_generation,
                material.service_generation_digest,
            )
        except Exception:
            raise AuthorityDenied("native.health.principal", "selected health principal is unavailable") from None
        if (getattr(principal, "principal_id", None) != material.principal_id
                or getattr(principal, "uid", None) != getattr(operation, "service_uid", None)
                or getattr(principal, "namespace_id", None)
                != material.namespace_identity
                or getattr(operation, "service_gid", None) != getattr(profile, "service_gid",
                                                                        getattr(profile, "owner_gid", None))):
            raise AuthorityDenied("native.health.principal", "selected health profile identity changed")
        source_closure = material.source_binding
        source_digest = getattr(source_closure, "source_closure_sha256", None)
        source_handles = getattr(source_closure, "source_receipt_handles", None)
        if (not isinstance(source_digest, str) or not _SHA256.fullmatch(source_digest)
                or not isinstance(source_handles, tuple) or not source_handles
                or not all(_OPAQUE.fullmatch(item) for item in source_handles)):
            raise AuthorityDenied("native.health.source", "selected health source closure is unavailable")
        now = self.monotonic()
        expiry = min(now + 30.0, float(receipt.expires_monotonic),
                     float(material.controller_lease.expires_monotonic))
        if expiry <= now:
            raise AuthorityDenied("native.health.expired", "committed health admission is already expired")
        handle = secrets.token_urlsafe(32)
        admission = RootNativeHealthStartAdmission(
            schema=1, admission_handle=handle,
            committed_enrollment_receipt_handle=committed_enrollment_receipt_handle,
            committed_enrollment_receipt_id=commit.journal_transaction_id,
            bootstrap_transaction_handle=receipt.transaction_handle,
            enrollment_id=material.enrollment_id, profile_id=material.profile_id,
            principal_id=material.principal_id, process_generation=material.process_generation,
            service_generation_digest=material.service_generation_digest,
            operation_id=_HEALTH_OPERATION,
            parameter_schema_id=_HEALTH_PARAMETER_SCHEMA,
            parameter_schema_sha256=material.parameter_schema_sha256,
            recipe_sha256=material.recipe_sha256,
            health_fixture_artifact_id=material.health_fixture_artifact_id,
            health_fixture_sha256=material.health_fixture_sha256,
            health_fixture_receipt_handle=material.health_fixture_receipt_handle,
            health_result_schema_id=material.health_result_schema_id,
            health_result_schema_sha256=material.health_result_schema_sha256,
            native_package_id=material.native_package_id,
            native_package_generation=material.native_package_generation,
            native_closure_sha256=material.native_closure_sha256,
            controller_binding_handle=material.controller_binding_handle,
            issued_monotonic=now, expires_monotonic=expiry,
            _instance_seal=self._seal, _verified_commit=commit,
            _service_profile=profile, _process_operation=operation,
            _controller_lease=material.controller_lease,
            _fixture_bytes=material.fixture_bytes, _source_binding=source_closure,
            _namespace_identity=material.namespace_identity,
        )
        with self._lock:
            if handle in self._admissions:
                raise AuthorityDenied("native.health.handle", "health admission handle collision")
            self._admissions[handle] = admission
        return handle

    def resolve_current_health_admission(self, admission_handle: str) -> RootNativeHealthStartAdmission:
        if not _OPAQUE.fullmatch(admission_handle):
            raise AuthorityDenied("native.health.admission", "health admission handle is malformed")
        with self._lock:
            admission = self._admissions.get(admission_handle)
        if (admission is None or admission._instance_seal is not self._seal
                or admission.admission_handle != admission_handle or not self.is_current(admission)):
            raise AuthorityDenied("native.health.admission", "health admission is stale or unknown")
        return admission

    def resolve_current_health_admission_for_commit(
        self, commit: Any,
    ) -> RootNativeHealthStartAdmission:
        """Return the unique retained current admission for an exact store proof."""
        from .bootstrap_enrollment import VerifiedCommittedEnrollment
        if type(commit) is not VerifiedCommittedEnrollment:
            raise AuthorityDenied("native.health.admission", "health admission requires a verified committed enrollment")
        with self._lock:
            matches = tuple(admission for admission in self._admissions.values()
                            if admission._verified_commit is commit)
        current = tuple(admission for admission in matches if self.is_current(admission))
        if len(current) != 1:
            raise AuthorityDenied("native.health.admission", "current health admission is absent or ambiguous")
        return current[0]

    def resolve_current_daemon_health_admission(
            self, proof: RootDaemonCommittedHealthProof) -> RootNativeHealthStartAdmission:
        if (not self.daemon_mode or type(proof) is not RootDaemonCommittedHealthProof
                or proof._registry is not self.committed_enrollment_registry):
            raise AuthorityDenied("native.health.daemon_admission", "exact current daemon commit proof is required")
        with self._lock:
            matches = tuple(item for item in self._admissions.values()
                            if item.authority_branch == "daemon-committed"
                            and item._verified_commit is proof)
        current = tuple(item for item in matches if self.is_current(item))
        if len(current) != 1:
            raise AuthorityDenied("native.health.daemon_admission", "unique current daemon admission is unavailable")
        return current[0]

    def resolve_current_daemon_health_admission_for_intent(
            self, intent_handle: str) -> RootNativeHealthStartAdmission:
        """Resolve the exact already-admitted in-process run for a durable intent."""
        if not self.daemon_mode or not _OPAQUE.fullmatch(intent_handle):
            raise AuthorityDenied("native.health.daemon_admission", "daemon intent handle is malformed")
        with self._lock:
            matches = tuple(
                admission for handle, admission in self._admissions.items()
                if self._daemon_intents.get(handle, (None, None))[0] == intent_handle
            )
        current = tuple(admission for admission in matches if self.is_current(admission))
        if len(current) != 1:
            raise AuthorityDenied("native.health.daemon_admission", "unique retained intent admission is unavailable")
        return current[0]

    def resolve_selected_recipe_binding(self, admission: RootNativeHealthStartAdmission,
                                        role: str, action: str) -> RootSelectedHealthStartBinding:
        current = self.resolve_current_health_admission(admission.admission_handle)
        if current is not admission or role != "health" or action != "start":
            raise AuthorityDenied("native.health.binding", "health action is outside the fixed start role")
        return self._binding(admission)

    def resolve_health_controller_proof(
        self, controller_binding_handle: str, admission_handle: str,
    ) -> Any:
        admission = self.resolve_current_health_admission(admission_handle)
        if admission.controller_binding_handle != controller_binding_handle:
            raise AuthorityDenied("native.health.controller", "controller binding does not join this admission")
        if admission.authority_branch == "daemon-committed":
            lease = admission._controller_lease
            if type(lease) is not RootDaemonHealthControllerLease or not lease.is_current():
                raise AuthorityDenied("native.health.controller", "daemon MainPID lease is no longer current")
            return lease
        from .selected_startup_authority import RootControllerProcessIdentityLease
        lease = admission._controller_lease
        if type(lease) is not RootControllerProcessIdentityLease or not lease.is_current():
            raise AuthorityDenied("native.health.controller", "root controller PIDFD is no longer current")
        try:
            return RootControllerProcessIdentityLease(
                proof_handle=lease.proof_handle,
                startup_authorization_handle=lease.startup_authorization_handle,
                pid=lease.pid, uid=lease.uid, start_ticks=lease.start_ticks,
                pidfd=os.dup(lease.pidfd), cgroup_identity=lease.cgroup_identity,
                mount_namespace_inode=lease.mount_namespace_inode,
                network_namespace_inode=lease.network_namespace_inode,
                proof_sha256=lease.proof_sha256,
                expires_monotonic=lease.expires_monotonic,
                _current_check=lease._current_check, _monotonic=self.monotonic,
            )
        except OSError:
            raise AuthorityDenied("native.health.controller", "root controller PIDFD could not be duplicated") from None

    def is_current(self, admission: RootNativeHealthStartAdmission) -> bool:
        if (type(admission) is not RootNativeHealthStartAdmission
                or admission._instance_seal is not self._seal
                or admission.expires_monotonic <= self.monotonic()
                or not admission._controller_lease.is_current()):
            return False
        if admission.authority_branch == "daemon-committed":
            if not self.daemon_mode or admission._verified_commit is None:
                return False
            try:
                proof = admission._verified_commit
                from .native_health_observer import RootDaemonCommittedHealthProof
                if (type(proof) is not RootDaemonCommittedHealthProof
                        or proof._registry is not self.committed_enrollment_registry
                        or not self.committed_enrollment_registry.is_current_commit(proof)
                        or self.daemon_material_registry.is_current(
                            admission._source_material) is not True):
                    return False
                with self._lock:
                    retained = self._admissions.get(admission.admission_handle)
                    material = self._daemon_materials.get(admission.admission_handle)
                    intent = self._daemon_intents.get(admission.admission_handle)
                if (retained is not admission or material is not admission._source_material
                        or material._commit_proof is not proof or intent is None
                        or intent[0] != proof.intent_handle
                        or proof.committed_transaction_id != admission.committed_enrollment_receipt_id
                        or proof.bootstrap_transaction_handle != admission.bootstrap_transaction_handle
                        or proof.service_generation_digest != admission.service_generation_digest
                        or proof.generation_id != material.generation_id
                        or proof.health_definition_sha256 != material.health_definition_sha256
                        or material.controller_binding_handle != admission.controller_binding_handle
                        or material._controller_lease is not admission._controller_lease
                        or material._source_binding is not admission._source_binding
                        or material._service_profile is not admission._service_profile
                        or material._process_operation is not admission._process_operation
                        or material.health_fixture_sha256 != admission.health_fixture_sha256
                        or material.native_closure_sha256 != admission.native_closure_sha256):
                    return False
                self.verified_installer_release.verify_current()
                self.current_installed_actor_verifier.verify_current(self.verified_installer_release)
                return admission._controller_lease.is_current()
            except Exception:
                return False
        try:
            self.verified_installer_release.verify_current()
            current_material = self.committed_enrollment_registry.resolve_current_health_material(
                    admission.committed_enrollment_receipt_handle, self.active_bindings,
                    self.verified_installer_release, self.current_installed_actor_verifier,
                )
            if type(current_material) is not RootNativeHealthStartMaterial:
                return False
            actor = self.current_installed_actor_verifier.verify_current(current_material.setup_plan)
            with self._lock:
                retained = self._admissions.get(admission.admission_handle)
            return bool(
                retained is admission and isinstance(actor, Mapping) and actor
                and current_material.verified_commit is admission._verified_commit
                and current_material.service_profile is admission._service_profile
                and current_material.process_operation is admission._process_operation
                and current_material.controller_lease.proof_sha256 == admission._controller_lease.proof_sha256
                and current_material.enrollment_id == admission.enrollment_id
                and current_material.profile_id == admission.profile_id
                and current_material.principal_id == admission.principal_id
                and current_material.process_generation == admission.process_generation
                and current_material.service_generation_digest == admission.service_generation_digest
                and current_material.health_fixture_artifact_id == admission.health_fixture_artifact_id
                and current_material.health_fixture_sha256 == admission.health_fixture_sha256
                and current_material.health_fixture_receipt_handle == admission.health_fixture_receipt_handle
                and current_material.health_result_schema_id == admission.health_result_schema_id
                and current_material.health_result_schema_sha256 == admission.health_result_schema_sha256
                and current_material.native_package_id == admission.native_package_id
                and current_material.native_package_generation == admission.native_package_generation
                and current_material.native_closure_sha256 == admission.native_closure_sha256
                and hashlib.sha256(current_material.fixture_bytes).hexdigest() == admission.health_fixture_sha256
                and self.committed_enrollment_registry.is_current(admission)
                and self.committed_enrollment_registry.is_current(admission)
            )
        except Exception:
            return False

    def _binding(self, admission: RootNativeHealthStartAdmission) -> RootSelectedHealthStartBinding:
        profile = admission._service_profile
        operation = admission._process_operation
        closure = admission._source_binding
        source_digest = getattr(closure, "source_closure_sha256",
                               getattr(closure, "native_closure_sha256", ""))
        source_handles = getattr(closure, "source_receipt_handles",
                                 getattr(closure, "source_member_receipt_handles", ()))
        return RootSelectedHealthStartBinding(
            role="health", action="start", service_enrollment_id=admission.enrollment_id,
            profile_id=admission.profile_id, generation=admission.process_generation,
            principal_id=admission.principal_id,
            namespace_identity=admission._namespace_identity,
            subject_uid=getattr(operation, "service_uid", 0),
            subject_gid=getattr(operation, "service_gid", 0),
            operation_id=admission.operation_id, operation="process.start",
            capability="hermes-profile-invoke",
            target=getattr(operation, "target", ""),
            recipe_sha256=admission.recipe_sha256,
            source_closure_sha256=source_digest,
            source_receipt_handles=source_handles,
            controller_proof_sha256=admission._controller_lease.proof_sha256,
            service_profile=profile, process_operation=operation,
            source_closure=closure,
        )

    def start_selected_health(self, admission_handle: str) -> Any:
        admission = self.resolve_current_health_admission(admission_handle)
        with self._lock:
            if admission_handle in self._used:
                raise AuthorityDenied("native.health.replay", "health start admission was already used")
            # A failed or ambiguous custody call cannot be retried under this
            # admission. A fresh live committed proof must be acquired instead.
            self._used.add(admission_handle)
        binding = self._binding(admission)
        payload = binding.payload()
        grant = self.authority_service.issue_root_selected_service_effect(
            admission, binding, "start", payload,
        )
        verified = self.authority_service.consume_root_selected_service_effect(
            grant, admission, binding.service_profile, payload,
        )
        if (not getattr(verified, "is_current", lambda: False)()
                or getattr(verified, "admission_handle", None) != admission_handle
                or getattr(verified, "role", None) != "health"
                or getattr(verified, "action", None) != "start"
                or getattr(verified, "request_sha256", None) != hashlib.sha256(payload).hexdigest()
                or not self.verify_consumed_start_effect(verified, admission)):
            close = getattr(verified, "close", None)
            if callable(close):
                close()
            raise AuthorityDenied("native.health.grant", "consumed health effect is not bound to this admission")
        if not self.is_current(admission):
            verified.close()
            raise AuthorityDenied("native.health.stale", "health admission changed before custody start")
        try:
            control = self.managed_process_custody.start_selected_health_operation(
                verified, admission_handle,
            )
        except Exception:
            verified.close()
            raise
        # Custody owns observer.begin_selected_health(control) before fixture
        # delivery. Requiring the exact returned type is deferred to custody's
        # exported RootSelectedHealthControl to avoid a parallel DTO.
        with self._lock:
            self._started[admission_handle] = control
        return control

    def verify_consumed_start_effect(self, effect: Any,
                                    admission: RootNativeHealthStartAdmission) -> bool:
        if (getattr(effect, "_service", None) is not self.authority_service
                or getattr(effect, "admission_handle", None) != admission.admission_handle
                or getattr(effect, "admission_kind", None) != "health"
                or getattr(effect, "role", None) != "health"
                or getattr(effect, "action", None) != "start"
                or getattr(effect, "operation_id", None) != _HEALTH_OPERATION
                or getattr(effect, "profile_id", None) != admission.profile_id
                or getattr(effect, "generation", None) != admission.process_generation
                or getattr(effect, "enrollment_id", None) != admission.enrollment_id
                or getattr(effect, "recipe_sha256", None) != admission.recipe_sha256
                or not effect.is_current()):
            return False
        entries = getattr(self.authority_service, "_root_selected_service_effects", {})
        return any(entry.get("verified") is effect and entry.get("admission") is admission
                   and entry.get("state") == "consumed" for entry in entries.values())


@dataclass(frozen=True, slots=True)
class RootSelectedNativeHealthRun:
    """Current root-selected health process and its immutable enrollment joins.

    ``selected_health_resolver`` returns this only after resolving the opaque
    lifecycle control handle to the committed enrollment transaction and
    starting the fixed root-selected health recipe under custody.
    """

    operation_id: str
    enrollment_id: str
    profile_id: str
    process_generation: str
    service_generation_digest: str
    bootstrap_transaction_handle: str
    committed_enrollment_receipt_id: str
    intent_handle: str
    process_id: str
    process_pid: int
    process_pidfd: int
    process_uid: int
    process_identity: Any
    package_id: str
    compiled_closure_sha256: str
    loaded_package_proof: Any
    fixture_artifact_id: str
    fixture_sha256: str
    health_action_id: str
    result_schema_id: str
    provider_required: bool
    parent_closure_digest: str | None
    expires_monotonic: float

    def __post_init__(self) -> None:
        for name in ("operation_id", "enrollment_id", "profile_id", "process_generation",
                     "bootstrap_transaction_handle", "committed_enrollment_receipt_id",
                     "intent_handle", "process_id", "package_id", "fixture_artifact_id", "health_action_id",
                     "result_schema_id"):
            if not _identifier(getattr(self, name)):
                raise ValueError(f"selected health run {name} is invalid")
        for name in ("service_generation_digest", "compiled_closure_sha256", "fixture_sha256"):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"selected health run {name} is invalid")
        if (self.parent_closure_digest is not None
                and not _SHA256.fullmatch(self.parent_closure_digest)):
            raise ValueError("selected health run parent closure digest is invalid")
        if not _OPAQUE.fullmatch(self.intent_handle):
            raise ValueError("selected health run intent handle is invalid")
        if (type(self.process_pid) is not int or self.process_pid <= 0
                or type(self.process_pidfd) is not int or self.process_pidfd < 0
                or type(self.process_uid) is not int or self.process_uid <= 0
                or type(self.provider_required) is not bool
                or self.process_identity is None or self.loaded_package_proof is None
                or isinstance(self.expires_monotonic, bool)
                or type(self.expires_monotonic) not in (int, float)
                or not math.isfinite(self.expires_monotonic)):
            raise ValueError("selected health run live process or lease is invalid")


@dataclass(frozen=True, slots=True)
class RootNativeHealthEvent:
    """Typed event returned only by the root event-registry resolver."""

    event_id: str
    event_kind: str
    operation_id: str
    enrollment_id: str
    profile_id: str
    process_generation: str
    service_generation_digest: str
    process_id: str
    process_pid: int
    process_uid: int
    package_id: str
    compiled_closure_sha256: str
    parent_closure_digest: str | None
    observed_monotonic: float
    expires_monotonic: float
    loader_ready_event_id: str | None = None
    native_request_event_id: str | None = None
    provider_result_event_id: str | None = None
    tool_invocation_event_id: str | None = None
    tool_result_event_id: str | None = None
    terminal_receipt_handle: str | None = None
    result_schema_id: str | None = None
    result_bytes: bytes | None = None
    loaded_proof_id: str | None = None
    action_id: str | None = None
    provider_result_reference: str | None = None
    invocation_handle: str | None = None
    terminal_status: str | None = None
    cleanup_verified: bool = False
    ancestry_kind: str | None = None
    native_event_handle: str | None = None
    native_event_sha256: str | None = None
    causal_parent_event_ids: tuple[str, ...] = ()
    source_receipt_handles: tuple[str, ...] = ()
    source_receipt_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RootNativeHealthReceipt:
    schema: int
    health_receipt_handle: str
    operation_id: str
    enrollment_id: str
    profile_id: str
    process_generation: str
    service_generation_digest: str
    bootstrap_transaction_handle: str
    committed_enrollment_receipt_id: str
    process_id: str
    loader_ready_event_id: str
    native_request_event_id: str
    provider_result_event_id: str | None
    tool_invocation_event_id: str
    tool_result_event_id: str
    terminal_receipt_handle: str
    result_schema_id: str
    result_sha256: str
    parent_closure_digest: str
    health_run_proof_sha256: str
    status: str
    issued_monotonic: float
    expires_monotonic: float

    def __post_init__(self) -> None:
        if self.schema != 2 or not _OPAQUE.fullmatch(self.health_receipt_handle):
            raise ValueError("native health receipt handle is invalid")
        for name in ("operation_id", "enrollment_id", "profile_id", "process_generation",
                     "bootstrap_transaction_handle", "committed_enrollment_receipt_id", "process_id",
                     "loader_ready_event_id", "native_request_event_id", "tool_invocation_event_id",
                     "tool_result_event_id", "terminal_receipt_handle", "result_schema_id"):
            if not _identifier(getattr(self, name)):
                raise ValueError(f"native health receipt {name} is invalid")
        if self.provider_result_event_id is not None and not _identifier(self.provider_result_event_id):
            raise ValueError("native health provider event ID is invalid")
        for name in ("service_generation_digest", "result_sha256", "parent_closure_digest",
                     "health_run_proof_sha256"):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"native health receipt {name} is invalid")
        if (self.status not in {"passed", "failed", "incomplete"}
                or any(isinstance(value, bool) or type(value) not in (int, float)
                       or not math.isfinite(value)
                       for value in (self.issued_monotonic, self.expires_monotonic))
                or self.expires_monotonic <= self.issued_monotonic):
            raise ValueError("native health receipt status or lease is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class _RootHealthConsumptionTicket:
    """Ephemeral observer-issued proof for one retained pending receipt."""

    observer: Any = field(repr=False, compare=False)
    receipt: RootNativeHealthReceipt = field(repr=False, compare=False)
    active_receipt: Any = field(repr=False, compare=False)
    expected_service_generation_digest: str
    _seal: object = field(repr=False, compare=False)
    daemon_proof: Any = field(default=None, repr=False, compare=False)
    daemon_admission: Any = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class RootValidatedNativeHealthResult:
    """Reviewed semantic parser output; plain booleans/status strings are rejected."""

    result_schema_id: str
    result_sha256: str
    semantic_outcome: str


@dataclass(slots=True)
class _HealthObservation:
    handle: str
    control_handle: str
    run: RootSelectedNativeHealthRun
    process_pidfd: int
    loaded_package_proof: Any
    events: dict[str, RootNativeHealthEvent]
    expires_monotonic: float
    completed_terminal_proof: Any | None = None


def _validate_event_ancestry(event: RootNativeHealthEvent) -> bool:
    kinds = {"host-context-lineage-v1", "source-receipt-ids-v1", "custody-event-v1"}
    if (event.ancestry_kind not in kinds
            or not isinstance(event.native_event_handle, str)
            or not _OPAQUE.fullmatch(event.native_event_handle)
            or not isinstance(event.native_event_sha256, str)
            or not _SHA256.fullmatch(event.native_event_sha256)
            or not isinstance(event.causal_parent_event_ids, tuple)
            or any(not _identifier(value) for value in event.causal_parent_event_ids)
            or len(set(event.causal_parent_event_ids)) != len(event.causal_parent_event_ids)
            or not isinstance(event.source_receipt_handles, tuple)
            or not isinstance(event.source_receipt_ids, tuple)
            or any(not _OPAQUE.fullmatch(value) for value in event.source_receipt_handles)
            or any(not _identifier(value) for value in event.source_receipt_ids)
            or len(set(event.source_receipt_handles)) != len(event.source_receipt_handles)
            or tuple(sorted(event.source_receipt_ids)) != event.source_receipt_ids
            or len(set(event.source_receipt_ids)) != len(event.source_receipt_ids)
            or len(event.source_receipt_handles) != len(event.source_receipt_ids)):
        return False
    if event.event_kind in {"loader-ready", "terminal"}:
        return (event.ancestry_kind == "custody-event-v1"
                and event.parent_closure_digest is None
                and not event.source_receipt_handles and not event.source_receipt_ids)
    if (event.ancestry_kind == "custody-event-v1"
            or event.parent_closure_digest is None
            or not _SHA256.fullmatch(event.parent_closure_digest)
            or not event.source_receipt_handles):
        return False
    if event.ancestry_kind == "source-receipt-ids-v1":
        return event.parent_closure_digest == canonical_digest(list(event.source_receipt_ids))
    return event.ancestry_kind == "host-context-lineage-v1"


def _same_loaded_package_proof(expected: Any, current: Any) -> bool:
    """Join two fresh manager proofs by stable mount identity, not timestamp."""
    try:
        from hermes_installer.managed_process_custodian import RootSelectedHealthLoadedPackageProof
        if type(expected) is not RootSelectedHealthLoadedPackageProof:
            return False
        if type(current) is not RootSelectedHealthLoadedPackageProof:
            return False
        return (
            expected.proof_id == current.proof_id
            and expected.process_id == current.process_id
            and expected.profile_id == current.profile_id
            and expected.generation == current.generation
            and expected.kernel_uid == current.kernel_uid
            and expected.package_id == current.package_id
            and expected.compiled_closure_sha256 == current.compiled_closure_sha256
            and expected.service_generation_digest == current.service_generation_digest
        )
    except Exception:
        return False


def _health_run_proof_digest(run: RootSelectedNativeHealthRun,
                             events: list[RootNativeHealthEvent]) -> str:
    projection = {
        "schema": 1,
        "intent_handle": run.intent_handle,
        "committed_enrollment_receipt_id": run.committed_enrollment_receipt_id,
        "bootstrap_transaction_handle": run.bootstrap_transaction_handle,
        "service_generation_digest": run.service_generation_digest,
        "operation_id": run.operation_id,
        "enrollment_id": run.enrollment_id,
        "profile_id": run.profile_id,
        "process_generation": run.process_generation,
        "process_id": run.process_id,
        "package_id": run.package_id,
        "compiled_closure_sha256": run.compiled_closure_sha256,
        "fixture_sha256": run.fixture_sha256,
        "events": [{
            "event_id": event.event_id,
            "event_kind": event.event_kind,
            "native_event_handle": event.native_event_handle,
            "native_event_sha256": event.native_event_sha256,
            "ancestry_kind": event.ancestry_kind,
            "parent_closure_digest": event.parent_closure_digest,
            "source_receipt_ids": list(event.source_receipt_ids),
            "causal_parent_event_ids": list(event.causal_parent_event_ids),
        } for event in events],
    }
    return hashlib.sha256(canonical_bytes(projection)).hexdigest()


def _ordered_health_events(events: Mapping[str, RootNativeHealthEvent],
                           provider_required: bool
                           ) -> tuple[dict[str, RootNativeHealthEvent], list[RootNativeHealthEvent]]:
    by_kind: dict[str, RootNativeHealthEvent] = {}
    for event in events.values():
        if event.event_kind in by_kind:
            raise AuthorityDenied("native.health.ambiguous", "health run has duplicate semantic event kinds")
        by_kind[event.event_kind] = event
    required = {"loader-ready", "native-request", "tool-invocation", "tool-result", "terminal"}
    if provider_required:
        required.add("provider-result")
    if required - set(by_kind):
        raise AuthorityDenied("native.health.incomplete", "selected health run lacks required native events")
    loader, request = by_kind["loader-ready"], by_kind["native-request"]
    invocation, tool_result, terminal = (
        by_kind["tool-invocation"], by_kind["tool-result"], by_kind["terminal"])
    provider = by_kind.get("provider-result")
    ordered = [loader, request]
    if provider is not None:
        ordered.append(provider)
    ordered.extend((invocation, tool_result, terminal))
    expected_parents = {
        "loader-ready": (),
        "native-request": (loader.event_id,),
        "provider-result": (request.event_id,),
        "tool-invocation": ((provider.event_id,) if provider is not None else (request.event_id,)),
        "tool-result": (invocation.event_id,),
        "terminal": (tool_result.event_id,),
    }
    if any(not _validate_event_ancestry(event)
           or event.causal_parent_event_ids != expected_parents[event.event_kind]
           for event in ordered):
        raise AuthorityDenied("native.health.lineage", "health event ancestry or causal parent DAG is invalid")
    return by_kind, ordered


class RootNativeHealthObserver:
    """Join actual selected loader, request, result, tool, and terminal events."""

    def __init__(self, *, selected_health_resolver: Callable[[str], RootSelectedNativeHealthRun],
                 event_resolver: Callable[[str, str], RootNativeHealthEvent],
                 process_resolver: Callable[..., Any],
                 loaded_package_proof_resolver: Callable[[RootSelectedNativeHealthRun], Any],
                 result_validator: Callable[[str, bytes], Any],
                 selected_run_canceller: Callable[[RootSelectedNativeHealthRun], None],
                 terminal_proof_resolver: Callable[[str, str], Any] | None = None,
                 completed_event_resolver: Callable[[str, str, Any], RootNativeHealthEvent] | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
        if (not all(callable(value) for value in (
                selected_health_resolver, event_resolver, process_resolver,
                loaded_package_proof_resolver, result_validator,
                selected_run_canceller, monotonic))):
            raise ValueError("root native health observation requires concrete root adapters")
        self.selected_health_resolver = selected_health_resolver
        self.event_resolver = event_resolver
        self.process_resolver = process_resolver
        self.loaded_package_proof_resolver = loaded_package_proof_resolver
        self.result_validator = result_validator
        self.selected_run_canceller = selected_run_canceller
        self.terminal_proof_resolver = terminal_proof_resolver
        self.completed_event_resolver = completed_event_resolver
        self.monotonic = monotonic
        self._observations: dict[str, _HealthObservation] = {}
        self._receipts: dict[str, RootNativeHealthReceipt] = {}
        self._receipt_runs: dict[str, tuple[RootSelectedNativeHealthRun,
                                            Mapping[str, RootNativeHealthEvent], str, str, Any]] = {}
        self._consumed: set[str] = set()
        self._consumption_tickets: dict[str, _RootHealthConsumptionTicket] = {}
        self._consumption_seal = object()
        self._lock = threading.RLock()

    def begin_selected_health(self, control_handle: str) -> str:
        if not _OPAQUE.fullmatch(control_handle):
            raise AuthorityDenied("native.health.control", "root health control handle is malformed")
        try:
            run = self.selected_health_resolver(control_handle)
        except Exception:
            raise AuthorityDenied("native.health.selection", "selected committed health run is unavailable") from None
        if type(run) is not RootSelectedNativeHealthRun:
            raise AuthorityDenied("native.health.selection", "health resolver did not return the root selected-run DTO")
        now = self.monotonic()
        if now >= run.expires_monotonic:
            self.selected_run_canceller(run)
            raise AuthorityDenied("native.health.expired", "selected health run expired before observation")
        identity = self.process_resolver(
            run.process_pid, run.process_pidfd, profile_id=run.profile_id,
            generation=run.process_generation,
        )
        proof = self.loaded_package_proof_resolver(run)
        if (identity is None or identity != run.process_identity
                or identity.kernel_uid != run.process_uid
                or not _same_loaded_package_proof(run.loaded_package_proof, proof)
                or getattr(proof, "package_id", None) != run.package_id
                or getattr(proof, "compiled_closure_sha256", None) != run.compiled_closure_sha256
                or getattr(proof, "profile_id", None) != run.profile_id
                or getattr(proof, "generation", None) != run.process_generation
                or getattr(proof, "service_generation_digest", None) != run.service_generation_digest):
            self.selected_run_canceller(run)
            raise AuthorityDenied("native.health.closure", "active process or loaded package closure is unavailable")
        try:
            pidfd = os.dup(run.process_pidfd)
        except OSError:
            self.selected_run_canceller(run)
            raise AuthorityDenied("native.health.peer", "health process PIDFD could not be retained") from None
        handle = secrets.token_urlsafe(32)
        observation = _HealthObservation(
            handle, control_handle, run, pidfd, proof, {}, run.expires_monotonic,
        )
        with self._lock:
            if handle in self._observations or handle in self._receipts:
                os.close(pidfd)
                self.selected_run_canceller(run)
                raise AuthorityDenied("native.health.handle", "health handle collision")
            self._observations[handle] = observation
        return handle

    def resolve_current_run_for_observation(
            self, health_observation_handle: str) -> RootSelectedNativeHealthRun:
        """Return only the same live run retained when observation began."""
        if not _OPAQUE.fullmatch(health_observation_handle):
            raise AuthorityDenied("native.health.observation", "health observation handle is malformed")
        with self._lock:
            observation = self._observations.get(health_observation_handle)
            if (observation is None or observation.handle != health_observation_handle
                    or self.monotonic() >= observation.expires_monotonic
                    or _pidfd_exited(observation.process_pidfd)):
                raise AuthorityDenied("native.health.observation", "retained health run is no longer current")
            run = observation.run
            identity = self.process_resolver(
                run.process_pid, observation.process_pidfd,
                profile_id=run.profile_id, generation=run.process_generation,
            )
            package = self.loaded_package_proof_resolver(run)
            if (identity is None or identity != run.process_identity
                    or getattr(package, "package_id", None) != run.package_id
                    or getattr(package, "compiled_closure_sha256", None) != run.compiled_closure_sha256
                    or getattr(package, "profile_id", None) != run.profile_id
                    or getattr(package, "generation", None) != run.process_generation
                    or getattr(package, "service_generation_digest", None) != run.service_generation_digest):
                raise AuthorityDenied("native.health.observation", "retained health process or package changed")
            if self._observations.get(health_observation_handle) is not observation:
                raise AuthorityDenied("native.health.observation", "retained health run changed during resolution")
            return run

    def observe_health_event(self, health_observation_handle: str,
                             root_event_record: str) -> None:
        if not _OPAQUE.fullmatch(health_observation_handle) or not _OPAQUE.fullmatch(root_event_record):
            raise AuthorityDenied("native.health.event", "root health event reference is malformed")
        with self._lock:
            observation = self._observations.get(health_observation_handle)
        if observation is None:
            raise AuthorityDenied("native.health.handle", "health observation is unknown or finished")
        run = observation.run
        now = self.monotonic()
        if now >= observation.expires_monotonic:
            self._retire_observation(observation, cancel=True)
            raise AuthorityDenied("native.health.expired", "health observation lease expired")
        try:
            event = self.event_resolver(health_observation_handle, root_event_record)
        except Exception:
            raise AuthorityDenied("native.health.event", "root event registry did not resolve this event") from None
        if type(event) is not RootNativeHealthEvent:
            raise AuthorityDenied("native.health.event", "event registry returned an untyped health record")
        if (event.event_id != root_event_record or event.event_kind not in _EVENT_KINDS
                or not _validate_event_ancestry(event)
                or event.operation_id != run.operation_id
                or event.enrollment_id != run.enrollment_id
                or event.profile_id != run.profile_id
                or event.process_generation != run.process_generation
                or event.service_generation_digest != run.service_generation_digest
                or event.process_id != run.process_id
                or event.process_pid != run.process_pid or event.process_uid != run.process_uid
                or event.package_id != run.package_id
                or event.compiled_closure_sha256 != run.compiled_closure_sha256
                or type(event.observed_monotonic) not in (int, float)
                or not math.isfinite(event.observed_monotonic)
                or event.observed_monotonic > now
                or type(event.expires_monotonic) not in (int, float)
                or not math.isfinite(event.expires_monotonic)
                or event.expires_monotonic > observation.expires_monotonic
                or event.expires_monotonic <= now):
            raise AuthorityDenied("native.health.event_binding", "health event differs from selected current run")
        if event.event_kind != "terminal":
            current = self.process_resolver(
                run.process_pid, observation.process_pidfd,
                profile_id=run.profile_id, generation=run.process_generation,
            )
            proof = self.loaded_package_proof_resolver(run)
            if (current != run.process_identity
                    or not _same_loaded_package_proof(observation.loaded_package_proof, proof)):
                self._retire_observation(observation, cancel=True)
                raise AuthorityDenied("native.health.peer", "health process or loaded closure changed")
        else:
            observation.completed_terminal_proof = self._resolve_completed_terminal(observation, event)
        with self._lock:
            if event.event_id in observation.events:
                raise AuthorityDenied("native.health.replay", "health event was already recorded")
            observation.events[event.event_id] = event

    def _resolve_completed_terminal(self, observation: _HealthObservation,
                                    terminal: RootNativeHealthEvent) -> Any:
        """Rejoin dead-worker completion only through the manager's retained proof."""
        if self.terminal_proof_resolver is None:
            raise AuthorityDenied("native.health.terminal", "manager terminal proof resolver is unavailable")
        try:
            from hermes_installer.managed_process_custodian import (
                RootCompletedSelectedHealthTerminalProof,
                RootSelectedHealthControl,
                RootSelectedHealthTerminalReceipt,
            )
            from hermes_installer.authority.native_health_daemon import RootDaemonNativeHealthStartMaterial
            proof = self.terminal_proof_resolver(
                observation.control_handle, terminal.terminal_receipt_handle,
            )
        except Exception:
            raise AuthorityDenied("native.health.terminal", "manager terminal proof is unavailable") from None
        run = observation.run
        receipt = getattr(proof, "terminal_receipt", None)
        identity = getattr(proof, "process_identity", None)
        worker_view = getattr(proof, "observed_worker_view", None)
        expected_identity = run.process_identity
        if (type(proof) is not RootCompletedSelectedHealthTerminalProof
                or type(receipt) is not RootSelectedHealthTerminalReceipt
                or type(getattr(proof, "control", None)) is not RootSelectedHealthControl
                or type(getattr(proof, "admission", None)) is not RootNativeHealthStartAdmission
                or type(getattr(proof, "source_material", None)) is not RootDaemonNativeHealthStartMaterial
                or getattr(proof, "control_handle", None) != observation.control_handle
                or getattr(proof.control, "control_handle", None) != observation.control_handle
                or getattr(proof.admission, "_source_material", None) is not proof.source_material
                or getattr(proof.admission, "authority_branch", None) != "daemon-committed"
                or proof.control.process_id != run.process_id
                or proof.control.operation_id != run.operation_id
                or proof.control.enrollment_id != run.enrollment_id
                or proof.control.profile_id != run.profile_id
                or proof.control.process_generation != run.process_generation
                or proof.control.service_generation_digest != run.service_generation_digest
                or proof.control.bootstrap_transaction_handle != run.bootstrap_transaction_handle
                or proof.control.committed_enrollment_receipt_id != run.committed_enrollment_receipt_id
                or proof.control.health_fixture_artifact_id != run.fixture_artifact_id
                or proof.control.health_fixture_sha256 != run.fixture_sha256
                or proof.admission.operation_id != run.operation_id
                or proof.admission.enrollment_id != run.enrollment_id
                or proof.admission.profile_id != run.profile_id
                or proof.admission.process_generation != run.process_generation
                or proof.admission.service_generation_digest != run.service_generation_digest
                or proof.admission.health_fixture_artifact_id != run.fixture_artifact_id
                or proof.admission.health_fixture_sha256 != run.fixture_sha256
                or proof.admission.health_result_schema_id != run.result_schema_id
                or proof.admission.committed_enrollment_receipt_id != run.committed_enrollment_receipt_id
                or proof.admission.bootstrap_transaction_handle != run.bootstrap_transaction_handle
                or proof.source_material.health_fixture_artifact_id != run.fixture_artifact_id
                or proof.source_material.health_fixture_sha256 != run.fixture_sha256
                or proof.source_material.health_result_schema_id != run.result_schema_id
                or proof.source_material.health_provider_required is not run.provider_required
                or proof.source_material._health_definition.get("health_action_id") != run.health_action_id
                or proof.source_material.native_package_id != run.package_id
                or proof.source_material.native_closure_sha256 != run.compiled_closure_sha256
                or getattr(proof, "expires_monotonic", 0) <= self.monotonic()
                or not callable(getattr(proof, "is_current", None))
                or proof.is_current() is not True
                or receipt.terminal_receipt_handle != terminal.terminal_receipt_handle
                or receipt.control_handle != observation.control_handle
                or receipt.process_id != run.process_id
                or receipt.profile_id != run.profile_id
                or receipt.generation != run.process_generation
                or receipt.service_generation_digest != run.service_generation_digest
                or receipt.process_uid != run.process_uid
                or receipt.exit_code != 0 or receipt.timed_out or receipt.cancelled
                or receipt.output_overflow
                or not receipt.cleanup_verified or not receipt.cgroup_empty
                or not receipt.main_pidfd_gone or not receipt.launcher_reaped
                or terminal.terminal_status != "succeeded"
                or terminal.cleanup_verified is not True
                or terminal.terminal_receipt_handle != receipt.terminal_receipt_handle
                or terminal.loader_ready_event_id != receipt.loader_ready_event_id
                or getattr(proof, "loader_ready_event_id", None) != receipt.loader_ready_event_id
                or getattr(proof, "process_id", None) != run.process_id
                or getattr(proof, "process_pid", None) != run.process_pid
                or getattr(proof, "process_uid", None) != run.process_uid
                or getattr(proof, "profile_id", None) != run.profile_id
                or getattr(proof, "process_generation", None) != run.process_generation
                or getattr(proof, "service_generation_digest", None) != run.service_generation_digest
                or getattr(proof, "loaded_package_proof_id", None)
                    != getattr(observation.loaded_package_proof, "proof_id", None)
                or not _same_loaded_package_proof(
                    observation.loaded_package_proof, getattr(proof, "loaded_package_proof", None))
                or identity != expected_identity
                or worker_view is None
                or getattr(worker_view, "process_id", None) != run.process_id
                or getattr(worker_view, "process_pid", None) != run.process_pid
                or getattr(worker_view, "process_start_ticks", None)
                    != getattr(run.process_identity, "start_ticks", None)
                or getattr(proof, "process_start_ticks", None)
                    != getattr(run.process_identity, "start_ticks", None)
                or getattr(worker_view, "process_uid", None) != run.process_uid
                or getattr(proof, "process_uid", None) != run.process_uid
                or getattr(worker_view, "cgroup_identity", None)
                    != getattr(run.process_identity, "cgroup_identity", None)
                or getattr(proof, "cgroup_identity", None)
                    != getattr(run.process_identity, "cgroup_identity", None)
                or getattr(worker_view, "process_gid", None) != receipt.process_gid
                or getattr(proof, "process_gid", None) != receipt.process_gid
                or getattr(worker_view, "mount_namespace_inode", None)
                    != getattr(proof, "mount_namespace_inode", None)
                or getattr(worker_view, "network_namespace_inode", None)
                    != getattr(proof, "network_namespace_inode", None)
                or getattr(proof, "unit", None) != receipt.unit
                or getattr(proof, "executable_sha256", None)
                    != getattr(run.process_identity, "executable_sha256", None)):
            raise AuthorityDenied("native.health.terminal", "manager terminal proof differs from retained run")
        if (observation.completed_terminal_proof is not None
                and observation.completed_terminal_proof is not proof):
            raise AuthorityDenied("native.health.terminal", "manager terminal proof issuer identity changed")
        return proof

    def finish_selected_health(self, health_observation_handle: str) -> RootNativeHealthReceipt:
        with self._lock:
            observation = self._observations.get(health_observation_handle)
        if observation is None:
            raise AuthorityDenied("native.health.handle", "health observation is unknown or finished")
        run = observation.run
        if (self.monotonic() >= observation.expires_monotonic
                or self._observations.get(health_observation_handle) is not observation):
            raise AuthorityDenied("native.health.current", "selected run changed before causal proof closure")
        terminal_events = [event for event in observation.events.values()
                           if event.event_kind == "terminal"]
        if terminal_events:
            if len(terminal_events) != 1:
                raise AuthorityDenied("native.health.ambiguous", "health run has duplicate terminal events")
            self._resolve_completed_terminal(observation, terminal_events[0])
        else:
            current_identity = self.process_resolver(
                run.process_pid, observation.process_pidfd,
                profile_id=run.profile_id, generation=run.process_generation,
            )
            current_package = self.loaded_package_proof_resolver(run)
            if (current_identity != run.process_identity
                    or not _same_loaded_package_proof(observation.loaded_package_proof, current_package)):
                raise AuthorityDenied("native.health.current", "selected run changed before causal proof closure")
        for event in observation.events.values():
            try:
                if terminal_events:
                    if self.completed_event_resolver is None:
                        raise AuthorityDenied(
                            "native.health.current", "post-cleanup event issuer resolver is unavailable")
                    current_event = self.completed_event_resolver(
                        health_observation_handle, event.event_id,
                        observation.completed_terminal_proof,
                    )
                else:
                    current_event = self.event_resolver(health_observation_handle, event.event_id)
            except Exception:
                raise AuthorityDenied("native.health.current", "native source event changed before causal proof closure") from None
            if type(current_event) is not RootNativeHealthEvent or current_event is not event:
                raise AuthorityDenied("native.health.current", "native source event lost exact retained membership")
        by_kind, ordered_events = _ordered_health_events(
            observation.events, run.provider_required,
        )
        loader = by_kind["loader-ready"]
        request = by_kind["native-request"]
        invocation = by_kind["tool-invocation"]
        tool_result = by_kind["tool-result"]
        terminal = by_kind["terminal"]
        provider = by_kind.get("provider-result")
        if (loader.loader_ready_event_id != loader.event_id
                or loader.loaded_proof_id != getattr(observation.loaded_package_proof, "proof_id", None)
                or request.native_request_event_id != request.event_id
                or invocation.tool_invocation_event_id != invocation.event_id
                or invocation.action_id != run.health_action_id
                or tool_result.tool_result_event_id != tool_result.event_id
                or terminal.terminal_status != "succeeded" or terminal.cleanup_verified is not True
                or not isinstance(terminal.terminal_receipt_handle, str)
                or not _OPAQUE.fullmatch(terminal.terminal_receipt_handle)
                or (provider is not None and provider.provider_result_event_id != provider.event_id)
                or (provider is None and run.provider_required)):
            raise AuthorityDenied("native.health.events", "health event roles or terminal custody proof do not join")
        if (request.provider_result_event_id != (provider.event_id if provider else None)
                or (provider is not None and provider.native_request_event_id != request.event_id)
                or invocation.native_request_event_id != request.event_id
                or invocation.provider_result_reference != (provider.event_id if provider else None)
                or tool_result.tool_invocation_event_id != invocation.event_id):
            raise AuthorityDenied("native.health.lineage", "health request/provider/tool event ancestry does not join")
        if tool_result.invocation_handle != invocation.invocation_handle:
            raise AuthorityDenied("native.health.lineage", "health result is not bound to the selected invocation")
        result_bytes = tool_result.result_bytes
        if (tool_result.result_schema_id != run.result_schema_id
                or not isinstance(result_bytes, bytes) or not 1 <= len(result_bytes) <= 65_536):
            raise AuthorityDenied("native.health.result", "health result is not the selected bounded schema")
        result_digest = hashlib.sha256(result_bytes).hexdigest()
        try:
            validated = self.result_validator(run.result_schema_id, result_bytes)
        except Exception:
            raise AuthorityDenied("native.health.result", "reviewed health result validator rejected bytes") from None
        if (type(validated) is not RootValidatedNativeHealthResult
                or validated.result_schema_id != run.result_schema_id
                or validated.result_sha256 != result_digest
                or validated.semantic_outcome != "passed"):
            raise AuthorityDenied("native.health.semantic", "reviewed health result lacks semantic success")
        now = self.monotonic()
        if (now >= run.expires_monotonic
                or any(event.expires_monotonic <= now for event in observation.events.values())):
            self._retire_observation(observation, cancel=True)
            raise AuthorityDenied("native.health.expired", "health run or one of its events expired before receipt")
        if terminal_events:
            self._resolve_completed_terminal(observation, terminal)
        receipt_handle = secrets.token_urlsafe(32)
        proof_digest = _health_run_proof_digest(run, ordered_events)
        if tool_result.parent_closure_digest is None:
            raise AuthorityDenied("native.health.lineage", "tool result lacks its actual native source closure")
        receipt = RootNativeHealthReceipt(
            schema=2, health_receipt_handle=receipt_handle,
            operation_id=run.operation_id, enrollment_id=run.enrollment_id,
            profile_id=run.profile_id, process_generation=run.process_generation,
            service_generation_digest=run.service_generation_digest,
            bootstrap_transaction_handle=run.bootstrap_transaction_handle,
            committed_enrollment_receipt_id=run.committed_enrollment_receipt_id,
            process_id=run.process_id,
            loader_ready_event_id=loader.event_id,
            native_request_event_id=request.event_id,
            provider_result_event_id=provider.event_id if provider else None,
            tool_invocation_event_id=invocation.event_id,
            tool_result_event_id=tool_result.event_id,
            terminal_receipt_handle=terminal.terminal_receipt_handle,
            result_schema_id=run.result_schema_id, result_sha256=result_digest,
            parent_closure_digest=tool_result.parent_closure_digest,
            health_run_proof_sha256=proof_digest, status="passed",
            issued_monotonic=now,
            expires_monotonic=min(run.expires_monotonic,
                                  *(event.expires_monotonic for event in observation.events.values())),
        )
        with self._lock:
            if self._observations.pop(health_observation_handle, None) is not observation:
                os.close(observation.process_pidfd)
                raise AuthorityDenied("native.health.replay", "health observation changed before finish")
            os.close(observation.process_pidfd)
            self._receipts[receipt_handle] = receipt
            self._receipt_runs[receipt_handle] = (
                run, MappingProxyType({event.event_id: event for event in ordered_events}),
                health_observation_handle,
                proof_digest,
                observation.completed_terminal_proof,
            )
        return receipt

    def resolve_current_daemon_receipt(
            self, health_receipt_handle: str, proof: RootDaemonCommittedHealthProof,
            admission: RootNativeHealthStartAdmission
            ) -> tuple[RootNativeHealthReceipt, RootSelectedNativeHealthRun,
                       Mapping[str, RootNativeHealthEvent], str]:
        """Resolve the observer-issued receipt and its exact retained run/events."""
        from hermes_installer.managed_process_custodian import RootCompletedSelectedHealthTerminalProof
        with self._lock:
            receipt = self._receipts.get(health_receipt_handle)
            retained = self._receipt_runs.get(health_receipt_handle)
            if (receipt is None or retained is None or health_receipt_handle in self._consumed
                    or self.monotonic() >= receipt.expires_monotonic):
                raise AuthorityDenied("native.health.receipt", "daemon health receipt is absent, expired, or consumed")
            run, events, observation_handle, proof_digest, terminal_proof = retained
            if (type(proof) is not RootDaemonCommittedHealthProof
                    or type(admission) is not RootNativeHealthStartAdmission
                    or admission.authority_branch != "daemon-committed"
                    or admission._verified_commit is not proof
                    or receipt.committed_enrollment_receipt_id != proof.committed_transaction_id
                    or receipt.bootstrap_transaction_handle != proof.bootstrap_transaction_handle
                    or receipt.service_generation_digest != proof.service_generation_digest
                    or receipt.health_receipt_handle != health_receipt_handle
                    or receipt.status != "passed"
                    or run.committed_enrollment_receipt_id != proof.committed_transaction_id
                    or run.bootstrap_transaction_handle != proof.bootstrap_transaction_handle
                    or run.service_generation_digest != proof.service_generation_digest
                    or run.process_generation != admission.process_generation
                    or run.enrollment_id != admission.enrollment_id
                    or run.profile_id != admission.profile_id
                    or run.operation_id != admission.operation_id
                    or run.package_id != admission.native_package_id
                    or run.compiled_closure_sha256 != admission.native_closure_sha256
                    or run.fixture_artifact_id != admission.health_fixture_artifact_id
                    or run.fixture_sha256 != admission.health_fixture_sha256
                    or run.result_schema_id != admission.health_result_schema_id
                    or receipt.health_run_proof_sha256 != proof_digest
                    or _health_run_proof_digest(run, sorted(events.values(), key=lambda item: (
                        ("loader-ready", "native-request", "provider-result", "tool-invocation",
                         "tool-result", "terminal").index(item.event_kind), item.event_id))) != proof_digest
                    or run.provider_required != admission._source_material.health_provider_required
                    or any(type(event) is not RootNativeHealthEvent for event in events.values())):
                raise AuthorityDenied("native.health.receipt_binding", "passed receipt differs from the exact daemon admission/run")
            try:
                if (type(terminal_proof) is not RootCompletedSelectedHealthTerminalProof
                        or self.terminal_proof_resolver is None
                        or self.terminal_proof_resolver(
                            terminal_proof.control_handle,
                            terminal_proof.terminal_receipt.terminal_receipt_handle,
                        ) is not terminal_proof
                        or terminal_proof.is_current() is not True):
                    raise AuthorityDenied(
                        "native.health.current", "completed manager terminal proof is no longer current")
                event_resolver = self.completed_event_resolver
                if event_resolver is None or any(
                        event.expires_monotonic <= self.monotonic()
                        or event_resolver(observation_handle, event.event_id, terminal_proof) is not event
                        for event in events.values()):
                    raise AuthorityDenied(
                        "native.health.current", "retained native event ancestry is no longer current")
            except Exception:
                raise AuthorityDenied("native.health.current", "retained native event ancestry is no longer current")
            return receipt, run, events, proof_digest

    def consume_selected_health_receipt(self, health_receipt_handle: str,
                                        committed_enrollment_receipt_id: str,
                                        expected_service_generation_digest: str, *,
                                        completion_journal: Any | None = None,
                                        active_receipt: Any | None = None,
                                        daemon_commit_proof: Any | None = None,
                                        daemon_admission: Any | None = None) -> Any:
        if (not _OPAQUE.fullmatch(health_receipt_handle)
                or not _identifier(committed_enrollment_receipt_id)
                or not _SHA256.fullmatch(expected_service_generation_digest)):
            raise AuthorityDenied("native.health.receipt", "health receipt lookup is malformed")
        with self._lock:
            receipt = self._receipts.get(health_receipt_handle)
            if daemon_commit_proof is not None:
                if (type(daemon_commit_proof) is not RootDaemonCommittedHealthProof
                        or type(daemon_admission) is not RootNativeHealthStartAdmission
                        or daemon_admission.authority_branch != "daemon-committed"
                        or daemon_admission._verified_commit is not daemon_commit_proof
                        or not daemon_commit_proof._registry.is_current_commit(daemon_commit_proof)
                        or committed_enrollment_receipt_id != daemon_commit_proof.committed_transaction_id
                        or expected_service_generation_digest != daemon_commit_proof.service_generation_digest
                        or receipt is None):
                    raise AuthorityDenied("native.health.daemon_proof", "receipt consumption needs the exact current daemon commit")
                self.resolve_current_daemon_receipt(health_receipt_handle, daemon_commit_proof, daemon_admission)
            if (receipt is None or receipt.health_receipt_handle in self._consumed
                    or self.monotonic() >= receipt.expires_monotonic
                    or receipt.committed_enrollment_receipt_id != committed_enrollment_receipt_id
                    or receipt.service_generation_digest != expected_service_generation_digest
                    or receipt.status != "passed"):
                raise AuthorityDenied("native.health.receipt", "health receipt is stale, mismatched, or consumed")
            completion = receipt
            if completion_journal is not None:
                from .functional_health_receipt_consumer import (
                    RootDaemonFunctionalHealthCompletionWriter, RootFunctionalHealthJournal,
                )
                valid_journal = (type(completion_journal) is RootFunctionalHealthJournal
                                 if daemon_commit_proof is None else
                                 type(completion_journal) is RootDaemonFunctionalHealthCompletionWriter
                                 and completion_journal.health_observer is self)
                if (not valid_journal or active_receipt is None
                        or daemon_commit_proof is not None and (
                            completion_journal.daemon_admission is not daemon_admission
                            or completion_journal.daemon_commit_proof is not daemon_commit_proof)):
                    raise AuthorityDenied("native.health.journal", "health consumption requires the typed completion journal and commit")
                ticket = self._issue_consumption_ticket(
                    receipt, active_receipt, expected_service_generation_digest,
                    daemon_proof=daemon_commit_proof, daemon_admission=daemon_admission,
                )
                completion = completion_journal.persist_consumed_receipt(
                    ticket,
                )
            self._consumed.add(health_receipt_handle)
            self._consumption_tickets.pop(health_receipt_handle, None)
            return completion

    def _issue_consumption_ticket(self, receipt: RootNativeHealthReceipt,
                                  active_receipt: Any,
                                  expected_service_generation_digest: str, *,
                                  daemon_proof: Any = None,
                                  daemon_admission: Any = None) -> _RootHealthConsumptionTicket:
        """Mint a ticket only from the exact pending receipt while consume holds this lock."""
        if (self._receipts.get(receipt.health_receipt_handle) is not receipt
                or receipt.health_receipt_handle in self._consumed
                or self.monotonic() >= receipt.expires_monotonic
                or receipt.service_generation_digest != expected_service_generation_digest):
            raise AuthorityDenied("native.health.receipt", "health receipt is no longer pending consumption")
        ticket = _RootHealthConsumptionTicket(
            self, receipt, active_receipt, expected_service_generation_digest,
            self._consumption_seal, daemon_proof, daemon_admission,
        )
        self._consumption_tickets[receipt.health_receipt_handle] = ticket
        return ticket

    def _resolve_pending_consumption_ticket(
        self, ticket: Any,
    ) -> tuple[RootNativeHealthReceipt, Any, str]:
        """Check observer identity, seal, retained membership, lease and one-use state."""
        with self._lock:
            if (type(ticket) is not _RootHealthConsumptionTicket
                    or ticket.observer is not self or ticket._seal is not self._consumption_seal
                    or type(ticket.receipt) is not RootNativeHealthReceipt
                    or self._consumption_tickets.get(ticket.receipt.health_receipt_handle) is not ticket
                    or self._receipts.get(ticket.receipt.health_receipt_handle) is not ticket.receipt
                    or ticket.receipt.health_receipt_handle in self._consumed
                    or self.monotonic() >= ticket.receipt.expires_monotonic
                    or ticket.receipt.status != "passed"
                    or ticket.receipt.service_generation_digest
                    != ticket.expected_service_generation_digest):
                raise AuthorityDenied("native.health.receipt", "observer did not issue a current pending-consumption proof")
            return ticket.receipt, ticket.active_receipt, ticket.expected_service_generation_digest

    def cancel_selected_health(self, health_observation_handle: str) -> None:
        with self._lock:
            observation = self._observations.get(health_observation_handle)
        if observation is not None:
            self._retire_observation(observation, cancel=True)

    def _retire_observation(self, observation: _HealthObservation, *, cancel: bool) -> None:
        with self._lock:
            current = self._observations.pop(observation.handle, None)
        if current is None:
            return
        try:
            os.close(current.process_pidfd)
        except OSError:
            pass
        if cancel:
            try:
                self.selected_run_canceller(current.run)
            except Exception:
                pass


def _identifier(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 256
            and not any(ord(char) < 0x20 for char in value))
