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
import threading
import time
from dataclasses import dataclass, field
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
                or self._service_profile is None or self._process_operation is None
                or self._source_binding is None or self._controller_lease is None
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
                 monotonic: Callable[[], float] = time.monotonic):
        required = (
            (committed_enrollment_registry, "resolve_current_health_material"),
            (committed_enrollment_registry, "is_current"),
            (verified_installer_release, "verify_current"),
            (current_installed_actor_verifier, "verify_current"),
            (authority_service, "issue_root_selected_service_effect"),
            (authority_service, "consume_root_selected_service_effect"),
            (managed_process_custody, "start_selected_health_operation"),
            (health_observer, "begin_selected_health"),
        )
        if active_bindings is None or root_journal is None or not callable(monotonic) or any(
                not callable(getattr(owner, method, None)) for owner, method in required):
            raise AuthorityDenied("native.health.start.attach", "health start root dependencies are incomplete")
        self.active_bindings = active_bindings
        self.committed_enrollment_registry = committed_enrollment_registry
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
        self._used: set[str] = set()
        self._lock = threading.RLock()

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
        if not _OPAQUE.fullmatch(committed_enrollment_receipt_handle):
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
            source_closure_sha256=getattr(closure, "source_closure_sha256", ""),
            source_receipt_handles=getattr(closure, "source_receipt_handles", ()),
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
    parent_closure_digest: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        for name in ("operation_id", "enrollment_id", "profile_id", "process_generation",
                     "bootstrap_transaction_handle", "committed_enrollment_receipt_id",
                     "process_id", "package_id", "fixture_artifact_id", "health_action_id",
                     "result_schema_id"):
            if not _identifier(getattr(self, name)):
                raise ValueError(f"selected health run {name} is invalid")
        for name in ("service_generation_digest", "compiled_closure_sha256", "fixture_sha256",
                     "parent_closure_digest"):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"selected health run {name} is invalid")
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
    parent_closure_digest: str
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
    status: str
    issued_monotonic: float
    expires_monotonic: float

    def __post_init__(self) -> None:
        if self.schema != 1 or not _OPAQUE.fullmatch(self.health_receipt_handle):
            raise ValueError("native health receipt handle is invalid")
        for name in ("operation_id", "enrollment_id", "profile_id", "process_generation",
                     "bootstrap_transaction_handle", "committed_enrollment_receipt_id", "process_id",
                     "loader_ready_event_id", "native_request_event_id", "tool_invocation_event_id",
                     "tool_result_event_id", "terminal_receipt_handle", "result_schema_id"):
            if not _identifier(getattr(self, name)):
                raise ValueError(f"native health receipt {name} is invalid")
        if self.provider_result_event_id is not None and not _identifier(self.provider_result_event_id):
            raise ValueError("native health provider event ID is invalid")
        for name in ("service_generation_digest", "result_sha256", "parent_closure_digest"):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"native health receipt {name} is invalid")
        if (self.status not in {"passed", "failed", "incomplete"}
                or any(isinstance(value, bool) or type(value) not in (int, float)
                       or not math.isfinite(value)
                       for value in (self.issued_monotonic, self.expires_monotonic))
                or self.expires_monotonic <= self.issued_monotonic):
            raise ValueError("native health receipt status or lease is invalid")


@dataclass(frozen=True, slots=True)
class RootValidatedNativeHealthResult:
    """Reviewed semantic parser output; plain booleans/status strings are rejected."""

    result_schema_id: str
    result_sha256: str
    semantic_outcome: str


@dataclass(slots=True)
class _HealthObservation:
    handle: str
    run: RootSelectedNativeHealthRun
    process_pidfd: int
    loaded_package_proof: Any
    events: dict[str, RootNativeHealthEvent]
    expires_monotonic: float


class RootNativeHealthObserver:
    """Join actual selected loader, request, result, tool, and terminal events."""

    def __init__(self, *, selected_health_resolver: Callable[[str], RootSelectedNativeHealthRun],
                 event_resolver: Callable[[str, str], RootNativeHealthEvent],
                 process_resolver: Callable[..., Any],
                 loaded_package_proof_resolver: Callable[[RootSelectedNativeHealthRun], Any],
                 result_validator: Callable[[str, bytes], Any],
                 selected_run_canceller: Callable[[RootSelectedNativeHealthRun], None],
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
        self.monotonic = monotonic
        self._observations: dict[str, _HealthObservation] = {}
        self._receipts: dict[str, RootNativeHealthReceipt] = {}
        self._consumed: set[str] = set()
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
        observation = _HealthObservation(handle, run, pidfd, proof, {}, run.expires_monotonic)
        with self._lock:
            if handle in self._observations or handle in self._receipts:
                os.close(pidfd)
                self.selected_run_canceller(run)
                raise AuthorityDenied("native.health.handle", "health handle collision")
            self._observations[handle] = observation
        return handle

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
                or event.operation_id != run.operation_id
                or event.enrollment_id != run.enrollment_id
                or event.profile_id != run.profile_id
                or event.process_generation != run.process_generation
                or event.service_generation_digest != run.service_generation_digest
                or event.process_id != run.process_id
                or event.process_pid != run.process_pid or event.process_uid != run.process_uid
                or event.package_id != run.package_id
                or event.compiled_closure_sha256 != run.compiled_closure_sha256
                or event.parent_closure_digest != run.parent_closure_digest
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
            if current != run.process_identity or proof != observation.loaded_package_proof:
                self._retire_observation(observation, cancel=True)
                raise AuthorityDenied("native.health.peer", "health process or loaded closure changed")
        with self._lock:
            if event.event_id in observation.events:
                raise AuthorityDenied("native.health.replay", "health event was already recorded")
            observation.events[event.event_id] = event

    def finish_selected_health(self, health_observation_handle: str) -> RootNativeHealthReceipt:
        with self._lock:
            observation = self._observations.get(health_observation_handle)
        if observation is None:
            raise AuthorityDenied("native.health.handle", "health observation is unknown or finished")
        run = observation.run
        by_kind: dict[str, RootNativeHealthEvent] = {}
        for event in observation.events.values():
            if event.event_kind in by_kind:
                raise AuthorityDenied("native.health.ambiguous", "health run has duplicate semantic event kinds")
            by_kind[event.event_kind] = event
        required = {"loader-ready", "native-request", "tool-invocation", "tool-result", "terminal"}
        if run.provider_required:
            required.add("provider-result")
        missing = required - set(by_kind)
        if missing:
            raise AuthorityDenied("native.health.incomplete", "selected health run lacks required native events")
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
        receipt_handle = secrets.token_urlsafe(32)
        receipt = RootNativeHealthReceipt(
            schema=1, health_receipt_handle=receipt_handle,
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
            parent_closure_digest=run.parent_closure_digest, status="passed",
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
        return receipt

    def consume_selected_health_receipt(self, health_receipt_handle: str,
                                        committed_enrollment_receipt_id: str) -> RootNativeHealthReceipt:
        if (not _OPAQUE.fullmatch(health_receipt_handle)
                or not _identifier(committed_enrollment_receipt_id)):
            raise AuthorityDenied("native.health.receipt", "health receipt lookup is malformed")
        with self._lock:
            receipt = self._receipts.get(health_receipt_handle)
            if (receipt is None or receipt.health_receipt_handle in self._consumed
                    or self.monotonic() >= receipt.expires_monotonic
                    or receipt.committed_enrollment_receipt_id != committed_enrollment_receipt_id
                    or receipt.status != "passed"):
                raise AuthorityDenied("native.health.receipt", "health receipt is stale, mismatched, or consumed")
            self._consumed.add(health_receipt_handle)
            return receipt

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
