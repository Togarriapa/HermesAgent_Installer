"""Root-only selected memory service lifecycle bindings.

This module creates typed bindings for the v80 selected-service effect API.
The selected subject comes from the active service catalog; the controller
proof, consent, source closure, and currentness predicate are retained by the
root admission owner and are never serialized to a worker.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import time
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Callable, Mapping

from hermes_installer.memory.enrollment import MemoryLifecycleBinding, MemoryServiceEnrollment


_OPAQUE = re.compile(r"[A-Za-z0-9_-]{20,128}\Z", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ACTIONS = frozenset({"start", "status", "stop"})
_ADMISSION_SEAL = object()
_ROLE = {
    "openviking": "memory-openviking",
    "agentmemory": "memory-agentmemory",
    "claude-mem": "memory-claude-mem",
}


class MemoryLifecycleDenied(PermissionError):
    """Selected memory lifecycle has no current root-owned authority."""


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class MemorySelectedLifecycleActionBinding:
    """One fixed process action joined to a strict active memory enrollment."""

    role: str
    action: str
    service_enrollment_id: str
    generation: str
    profile_id: str
    principal_id: str
    namespace_identity: str
    subject_uid: int
    subject_gid: int
    operation: str
    capability: str
    target: str
    operation_id: str
    recipe_sha256: str
    source_closure_sha256: str
    source_receipt_handles: tuple[str, ...]
    service_profile: Any = field(repr=False, compare=False)
    process_operation: Any = field(repr=False, compare=False)
    _process_id: str | None = field(default=None, repr=False, compare=False)
    _stop_reason: str | None = field(default=None, repr=False, compare=False)

    @classmethod
    def resolve(cls, enrollment: MemoryServiceEnrollment, service_catalog: Any,
                *, action: str, source_closure_sha256: str,
                source_receipt_handles: tuple[str, ...],
                process_id: str | None = None) -> "MemorySelectedLifecycleActionBinding":
        if type(enrollment) is not MemoryServiceEnrollment or action not in _ACTIONS:
            raise MemoryLifecycleDenied("typed enrollment and fixed lifecycle action are required")
        lifecycle = enrollment.lifecycle_binding
        if lifecycle is None:
            raise MemoryLifecycleDenied("selected memory enrollment has no startup binding")
        if (not isinstance(source_closure_sha256, str) or not _DIGEST.fullmatch(source_closure_sha256)
                or not isinstance(source_receipt_handles, tuple) or not source_receipt_handles
                or any(not isinstance(handle, str) or not handle for handle in source_receipt_handles)
                or len(set(source_receipt_handles)) != len(source_receipt_handles)):
            raise MemoryLifecycleDenied("current source closure receipts are required")
        if action == "start":
            operation = "process.start"
            operation_id = lifecycle.start_operation_id
            if process_id is not None:
                raise MemoryLifecycleDenied("start cannot select an existing process handle")
        else:
            operation = "process.status" if action == "status" else "process.stop"
            operation_id = "managed-process-" + action + "-v1"
            if process_id is not None and (not isinstance(process_id, str)
                                           or not process_id or len(process_id) > 256):
                raise MemoryLifecycleDenied("status and stop process handle is malformed")
        try:
            profile = service_catalog.resolve(enrollment.service_enrollment_id,
                                              enrollment.service_generation)
            effect = service_catalog.resolve_operation(
                enrollment.service_enrollment_id, enrollment.service_generation, operation)
            recipe = (service_catalog.resolve_launch_recipe(
                enrollment.service_enrollment_id, enrollment.service_generation,
                operation_id) if action == "start" else None)
        except Exception:
            raise MemoryLifecycleDenied("selected service operation is absent from the active catalog") from None
        if (getattr(profile, "profile_id", None) != enrollment.profile_id
                or getattr(profile, "principal_id", None) != enrollment.principal_id
                or getattr(profile, "generation", None) != enrollment.service_generation
                or getattr(profile, "namespace_identity", None) != enrollment.namespace_identity
                or getattr(effect, "profile_id", None) != enrollment.profile_id
                or getattr(effect, "principal_id", None) != enrollment.principal_id
                or getattr(effect, "enrollment_id", None) != enrollment.service_enrollment_id
                or getattr(effect, "generation", None) != enrollment.service_generation
                or getattr(effect, "service_uid", None) != getattr(profile, "service_uid", None)
                or getattr(effect, "service_gid", None) != getattr(profile, "service_gid", None)
                or getattr(effect, "namespace_identity", None) != enrollment.namespace_identity):
            raise MemoryLifecycleDenied("selected operation does not join the exact enrolled memory service")
        if action == "start" and (
                getattr(recipe, "operation_id", None) != lifecycle.start_operation_id
                or getattr(recipe, "process_start_target", None) != effect.target_id):
            raise MemoryLifecycleDenied("memory start recipe differs from its fixed process target")
        capability = "hermes-profile-invoke" if operation == "process.start" else "hermes-process-control"
        identity = {
            "role": _ROLE[enrollment.provider], "action": action,
            "service_enrollment_id": enrollment.service_enrollment_id,
            "generation": enrollment.service_generation,
            "profile_id": enrollment.profile_id, "principal_id": enrollment.principal_id,
            "namespace_identity": enrollment.namespace_identity,
            "subject_uid": effect.service_uid, "subject_gid": effect.service_gid,
            "operation": operation, "capability": capability, "target": effect.target_id,
            "operation_id": operation_id,
            "recipe_sha256": _canonical_sha256({
                "operation_id": operation_id,
                "executable_sha256": getattr(recipe, "executable_sha256", ""),
                "argv_recipe": [dict(row) for row in getattr(getattr(recipe, "recipe", None), "argv_recipe", ())],
                "cwd_root_id": getattr(getattr(recipe, "recipe", None), "cwd_root_id", ""),
                "cwd_subpath": getattr(getattr(recipe, "recipe", None), "cwd_subpath", ""),
                "start_target": effect.target_id,
            }) if action == "start" else _canonical_sha256({
                "operation": operation, "target": effect.target_id,
                "enrollment_id": effect.enrollment_id, "generation": effect.generation,
            }),
            "source_closure_sha256": source_closure_sha256,
            "source_receipt_handles": list(source_receipt_handles),
        }
        return cls(
            role=identity["role"], action=action,
            service_enrollment_id=enrollment.service_enrollment_id,
            generation=enrollment.service_generation, profile_id=enrollment.profile_id,
            principal_id=enrollment.principal_id, namespace_identity=enrollment.namespace_identity,
            subject_uid=effect.service_uid, subject_gid=effect.service_gid,
            operation=operation, capability=capability, target=effect.target_id,
            operation_id=operation_id, recipe_sha256=identity["recipe_sha256"],
            source_closure_sha256=source_closure_sha256,
            source_receipt_handles=source_receipt_handles, service_profile=profile,
            process_operation=effect, _process_id=process_id,
        )

    def payload(self) -> bytes:
        """Serialize only the finite root-selected action payload."""
        if self.action == "start":
            value = {"schema": 1, "enrollment_id": self.service_enrollment_id,
                     "generation": self.generation, "operation_id": self.operation_id,
                     "parameters": {}}
        else:
            if not self._process_id:
                raise MemoryLifecycleDenied("selected process handle is no longer retained")
            value = {"schema": 1, "process_id": self._process_id,
                     "generation": self.generation}
            if self.action == "stop":
                if self._stop_reason not in {"cancel", "shutdown", "rollback"}:
                    raise MemoryLifecycleDenied("stop requires a root-selected cancellation reason")
                value.update(reason=self._stop_reason, grace_seconds=5)
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def with_retained_process(self, process_id: str) -> "MemorySelectedLifecycleActionBinding":
        """Bind controls to a process ID retained from this admission's launch receipt."""
        if (self.action not in {"status", "stop"} or not isinstance(process_id, str)
                or not process_id or len(process_id) > 256):
            raise MemoryLifecycleDenied("root-retained selected process identity is required")
        return replace(self, _process_id=process_id)

    def with_stop_reason(self, reason: str) -> "MemorySelectedLifecycleActionBinding":
        """Bind one finite root-selected stop reason to the stop payload."""
        if self.action != "stop" or reason not in {"cancel", "shutdown", "rollback"}:
            raise MemoryLifecycleDenied("stop reason is not one of the root-selected fixed reasons")
        return replace(self, _stop_reason=reason)

    def __repr__(self) -> str:
        return f"MemorySelectedLifecycleActionBinding(role={self.role!r}, action={self.action!r}, <root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootVerifiedMemoryLifecycleAdmission:
    """Sealed in-process proof for one current memory service lifecycle."""

    admission_handle: str
    service_generation_digest: str
    service_enrollment_id: str
    generation: str
    profile_id: str
    principal_id: str
    namespace_identity: str
    subject_uid: int
    subject_gid: int
    role: str
    memory_owner_generation: int
    consent_id: str
    consent_revision: str
    source_closure_sha256: str
    source_receipt_handles: tuple[str, ...]
    sensitivity: str
    issued_monotonic: float
    expires_monotonic: float
    original_deadline: float
    action_bindings: Mapping[str, MemorySelectedLifecycleActionBinding] = field(repr=False)
    _instance_seal: object = field(repr=False, compare=False)
    _controller_lease: Any = field(repr=False, compare=False)
    _enrollment: MemoryServiceEnrollment = field(repr=False, compare=False)
    _consent_record: Any = field(repr=False, compare=False)
    _source_closure: Any = field(repr=False, compare=False)
    _current_check: Callable[["RootVerifiedMemoryLifecycleAdmission"], bool] = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (not isinstance(self.admission_handle, str) or not _OPAQUE.fullmatch(self.admission_handle)
                or not _DIGEST.fullmatch(self.service_generation_digest)
                or not _DIGEST.fullmatch(self.source_closure_sha256)
                or not all(isinstance(value, str) and value for value in (
                    self.service_enrollment_id, self.generation, self.profile_id,
                    self.principal_id, self.namespace_identity, self.consent_id,
                    self.consent_revision, self.sensitivity))
                or type(self.subject_uid) is not int or self.subject_uid <= 0
                or type(self.subject_gid) is not int or self.subject_gid < 0
                or self.role not in set(_ROLE.values())
                or type(self.memory_owner_generation) is not int or self.memory_owner_generation < 1
                or not self.consent_id or not self.consent_revision
                or not isinstance(self.source_receipt_handles, tuple) or not self.source_receipt_handles
                or any(not isinstance(item, str) or not item for item in self.source_receipt_handles)
                or len(set(self.source_receipt_handles)) != len(self.source_receipt_handles)
                or not isinstance(self.action_bindings, Mapping)
                or set(self.action_bindings) - _ACTIONS
                or not {"start", "status", "stop"}.issubset(self.action_bindings)
                or any(type(binding) is not MemorySelectedLifecycleActionBinding
                       or binding.action != action or binding.role != self.role
                       for action, binding in self.action_bindings.items())
                or self._instance_seal is not _ADMISSION_SEAL
                or type(self._enrollment) is not MemoryServiceEnrollment
                or self._enrollment.service_enrollment_id != self.service_enrollment_id
                or self._enrollment.service_generation != self.generation
                or self._enrollment.profile_id != self.profile_id
                or self._enrollment.principal_id != self.principal_id
                or self._enrollment.namespace_identity != self.namespace_identity
                or self._enrollment.memory_owner_generation != self.memory_owner_generation
                or self._consent_record is None or self._source_closure is None
                or not callable(self._current_check)
                or not callable(getattr(self._controller_lease, "is_current", None))
                or isinstance(self.issued_monotonic, bool)
                or type(self.issued_monotonic) not in (int, float)
                or isinstance(self.expires_monotonic, bool)
                or type(self.expires_monotonic) not in (int, float)
                or self.expires_monotonic <= self.issued_monotonic
                or isinstance(self.original_deadline, bool)
                or type(self.original_deadline) not in (int, float)
                or self.original_deadline < self.expires_monotonic
                or self.original_deadline - self.issued_monotonic > 600):
            raise MemoryLifecycleDenied("root-verified memory lifecycle admission is malformed")
        expected_operations = {
            "start": ("process.start", "hermes-profile-invoke"),
            "status": ("process.status", "hermes-process-control"),
            "stop": ("process.stop", "hermes-process-control"),
        }
        life = self._enrollment.lifecycle_binding
        if life is None:
            raise MemoryLifecycleDenied("selected memory service has no source-backed start recipe")
        for action, binding in self.action_bindings.items():
            expected_operation, expected_capability = expected_operations[action]
            operation_binding = binding.process_operation
            if (binding.operation != expected_operation
                    or binding.capability != expected_capability
                    or binding.service_enrollment_id != self.service_enrollment_id
                    or binding.generation != self.generation
                    or binding.profile_id != self.profile_id
                    or binding.principal_id != self.principal_id
                    or binding.namespace_identity != self.namespace_identity
                    or binding.subject_uid != self.subject_uid
                    or binding.subject_gid != self.subject_gid
                    or binding.source_closure_sha256 != self.source_closure_sha256
                    or binding.source_receipt_handles != self.source_receipt_handles
                    or getattr(operation_binding, "operation", None) != expected_operation
                    or getattr(operation_binding, "target_id", None) != binding.target
                    or getattr(operation_binding, "enrollment_id", None) != self.service_enrollment_id
                    or getattr(operation_binding, "generation", None) != self.generation):
                raise MemoryLifecycleDenied("lifecycle action binding differs from sealed admission")
        if self.action_bindings["start"].operation_id != life.start_operation_id:
            raise MemoryLifecycleDenied("sealed memory start action differs from its fixed recipe")
        object.__setattr__(self, "action_bindings", MappingProxyType(dict(self.action_bindings)))

    @classmethod
    def _from_root_registry(cls, *, service_generation_digest: str,
                            enrollment: MemoryServiceEnrollment, consent_id: str,
                            consent_revision: str, source_closure_sha256: str,
                            source_receipt_handles: tuple[str, ...], sensitivity: str,
                            issued_monotonic: float, expires_monotonic: float,
                            original_deadline: float,
                            action_bindings: Mapping[str, MemorySelectedLifecycleActionBinding],
                            controller_lease: Any, consent_record: Any,
                            source_closure: Any,
                            current_check: Callable[["RootVerifiedMemoryLifecycleAdmission"], bool]
                            ) -> "RootVerifiedMemoryLifecycleAdmission":
        """Construct a sealed admission for a root-owned admission registry only."""
        try:
            from hermes_installer.authority.selected_startup_authority import (
                RootControllerProcessIdentityLease,
            )
        except ImportError:
            raise MemoryLifecycleDenied("selected service controller custody is unavailable") from None
        if type(enrollment) is not MemoryServiceEnrollment:
            raise MemoryLifecycleDenied("root memory service admission requires strict enrollment")
        if (not isinstance(controller_lease, RootControllerProcessIdentityLease)
                or not controller_lease.is_current()):
            raise MemoryLifecycleDenied("live root controller PIDFD proof is required")
        life = enrollment.lifecycle_binding
        if life is None:
            raise MemoryLifecycleDenied("selected memory enrollment has no startup binding")
        if set(action_bindings) != _ACTIONS:
            raise MemoryLifecycleDenied("all finite selected memory lifecycle actions must be bound")
        if any(binding.service_enrollment_id != enrollment.service_enrollment_id
               or binding.generation != enrollment.service_generation
               or binding.profile_id != enrollment.profile_id
               or binding.principal_id != enrollment.principal_id
               or binding.namespace_identity != enrollment.namespace_identity
               or binding.source_closure_sha256 != source_closure_sha256
               or binding.source_receipt_handles != source_receipt_handles
               for binding in action_bindings.values()):
            raise MemoryLifecycleDenied("lifecycle actions differ from the source-bound enrollment")
        if (not isinstance(service_generation_digest, str) or not _DIGEST.fullmatch(service_generation_digest)
                or not isinstance(consent_id, str) or not consent_id
                or not isinstance(consent_revision, str)
                or consent_revision != enrollment.background_consent_revision
                or not isinstance(sensitivity, str) or sensitivity not in {"PRIVATE", "CONFIDENTIAL"}
                or expires_monotonic <= issued_monotonic
                or original_deadline < expires_monotonic):
            raise MemoryLifecycleDenied("memory lifecycle consent, lineage, or deadline is invalid")
        return cls(
            admission_handle=new_memory_admission_handle(),
            service_generation_digest=service_generation_digest,
            service_enrollment_id=enrollment.service_enrollment_id,
            generation=enrollment.service_generation, profile_id=enrollment.profile_id,
            principal_id=enrollment.principal_id, namespace_identity=enrollment.namespace_identity,
            subject_uid=action_bindings["start"].subject_uid,
            subject_gid=action_bindings["start"].subject_gid,
            role=_ROLE[enrollment.provider],
            memory_owner_generation=enrollment.memory_owner_generation,
            consent_id=consent_id, consent_revision=consent_revision,
            source_closure_sha256=source_closure_sha256,
            source_receipt_handles=source_receipt_handles, sensitivity=sensitivity,
            issued_monotonic=issued_monotonic, expires_monotonic=expires_monotonic,
            original_deadline=original_deadline, action_bindings=action_bindings,
            _instance_seal=_ADMISSION_SEAL, _controller_lease=controller_lease,
            _enrollment=enrollment, _consent_record=consent_record,
            _source_closure=source_closure, _current_check=current_check,
        )

    def is_current(self, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        if (current >= min(self.expires_monotonic, self.original_deadline)
                or not self._controller_lease.is_current()):
            return False
        try:
            return bool(self._current_check(self))
        except Exception:
            return False

    def action(self, action: str, *, now: float | None = None,
               reason: str | None = None) -> MemorySelectedLifecycleActionBinding:
        if action not in _ACTIONS or not self.is_current(now=now):
            raise MemoryLifecycleDenied("memory service lifecycle admission is stale or action is invalid")
        binding = self.action_bindings.get(action)
        if binding is None:
            raise MemoryLifecycleDenied("memory lifecycle action is not selected")
        if action == "stop":
            binding = binding.with_stop_reason(reason or "shutdown")
        elif reason is not None:
            raise MemoryLifecycleDenied("a stop reason is valid only for the stop action")
        return binding

    def __repr__(self) -> str:
        return "RootVerifiedMemoryLifecycleAdmission(<root-private>)"


class RootMemoryServiceLifecycle:
    """Root-local issue/consume/custody path for enrolled memory service actions.

    Admissions are registered by the root memory admission owner after it has
    joined active enrollment, live consent, source closure, owner epoch and
    controller PIDFD. This class does not expose an admission RPC.
    """

    def __init__(self, *, authority_service: Any, custody: Any,
                 monotonic: Callable[[], float] = time.monotonic):
        if (authority_service is None
                or not callable(getattr(authority_service, "issue_root_selected_service_effect", None))
                or not callable(getattr(authority_service, "consume_root_selected_service_effect", None))
                or custody is None
                or not callable(getattr(custody, "perform_root_selected_service_effect", None))):
            raise MemoryLifecycleDenied("root selected memory lifecycle authority or custody is unavailable")
        self.authority_service = authority_service
        self.custody = custody
        self.monotonic = monotonic
        self._lock = __import__("threading").RLock()
        self._admissions: dict[str, RootVerifiedMemoryLifecycleAdmission] = {}
        self._process_ids: dict[str, str] = {}
        self._start_used: set[str] = set()
        self._restart_uses: dict[str, int] = {}
        self._stopped: set[str] = set()

    def retain_admission(self, admission: RootVerifiedMemoryLifecycleAdmission) -> None:
        """Retain only a live sealed admission created by the root registry."""
        if (type(admission) is not RootVerifiedMemoryLifecycleAdmission
                or admission._instance_seal is not _ADMISSION_SEAL
                or not admission.is_current(now=self.monotonic())):
            raise MemoryLifecycleDenied("only current root-issued memory lifecycle admissions may be retained")
        with self._lock:
            if admission.admission_handle in self._admissions:
                raise MemoryLifecycleDenied("memory lifecycle admission handle was already retained")
            self._admissions[admission.admission_handle] = admission
            self._restart_uses[admission.admission_handle] = 0

    def release_admission(self, handle: str) -> None:
        """Release one finite root-only admission after its effect completes."""
        if not isinstance(handle, str) or not _OPAQUE.fullmatch(handle):
            raise MemoryLifecycleDenied("memory lifecycle admission handle is malformed")
        with self._lock:
            admission = self._admissions.pop(handle, None)
            self._process_ids.pop(handle, None)
            self._restart_uses.pop(handle, None)
            self._start_used.discard(handle)
            self._stopped.discard(handle)
        if type(admission) is RootVerifiedMemoryLifecycleAdmission:
            close = getattr(admission._controller_lease, "close", None)
            if callable(close):
                close()

    def resolve_admission(self, handle: str) -> RootVerifiedMemoryLifecycleAdmission:
        if not isinstance(handle, str) or not _OPAQUE.fullmatch(handle):
            raise MemoryLifecycleDenied("root memory lifecycle admission handle is malformed")
        with self._lock:
            admission = self._admissions.get(handle)
        if (type(admission) is not RootVerifiedMemoryLifecycleAdmission
                or not admission.is_current(now=self.monotonic())):
            raise MemoryLifecycleDenied("memory lifecycle admission is stale or no longer enrolled")
        return admission

    @staticmethod
    def _process_id_from_receipt(receipt: Any, admission: RootVerifiedMemoryLifecycleAdmission) -> str:
        process_id = (receipt.get("process_id") if isinstance(receipt, Mapping)
                      else getattr(receipt, "process_id", None))
        generation = (receipt.get("generation") if isinstance(receipt, Mapping)
                      else getattr(receipt, "generation", None))
        if (not isinstance(process_id, str) or not process_id or len(process_id) > 256
                or generation != admission.generation):
            raise MemoryLifecycleDenied("custody start did not return the selected service process generation")
        return process_id

    def _effect(self, admission: RootVerifiedMemoryLifecycleAdmission,
                binding: MemorySelectedLifecycleActionBinding, *, timeout: float,
                cancelled: Callable[[], bool] | None) -> Any:
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or timeout <= 0
                or cancelled is not None and not callable(cancelled)):
            raise MemoryLifecycleDenied("memory lifecycle effect timeout or cancellation is invalid")
        if not admission.is_current(now=self.monotonic()):
            raise MemoryLifecycleDenied("selected memory lifecycle admission expired before effect")
        payload = binding.payload()
        grant = self.authority_service.issue_root_selected_service_effect(
            admission, binding, binding.action, payload,
        )
        if not admission.is_current(now=self.monotonic()):
            raise MemoryLifecycleDenied("selected memory lifecycle admission changed before grant consumption")
        verified = self.authority_service.consume_root_selected_service_effect(
            grant, admission, binding.service_profile, payload,
        )
        # The signed effect authorizes exactly one short-lived action. Custody
        # separately retains this sealed lifecycle admission's original service
        # deadline and the root controller's actual PIDFD proof; grant expiry
        # must not truncate a successfully supervised service lifetime.
        controller_proof = admission._controller_lease

        def effect_cancelled() -> bool:
            return (not admission.is_current(now=self.monotonic())
                    or cancelled is not None and cancelled())

        return self.custody.perform_root_selected_service_effect(
            binding.service_profile, verified, payload,
            memory_admission=admission,
            controller_proof=controller_proof,
            timeout=min(float(timeout), max(0.001, admission.original_deadline - self.monotonic())),
            cancelled=effect_cancelled,
        )

    def start_selected_memory(self, handle: str, *, timeout: float = 30.0,
                              cancelled: Callable[[], bool] | None = None) -> Any:
        admission = self.resolve_admission(handle)
        with self._lock:
            if handle in self._start_used and handle not in self._stopped:
                raise MemoryLifecycleDenied("memory service start is already active for this admission")
            if handle in self._start_used and handle in self._stopped:
                life = admission._enrollment.lifecycle_binding
                used = self._restart_uses.get(handle, 0)
                if (life is None or life.restart_policy != "bounded-owned-restart"
                        or used >= life.maximum_restart_attempts):
                    raise MemoryLifecycleDenied("memory lifecycle restart policy or quota denies restart")
                self._restart_uses[handle] = used + 1
            self._start_used.add(handle)
            self._stopped.discard(handle)
        # Keep the action consumed on every ambiguous error. Retrying a start
        # without a custody receipt can fork a second supervised service.
        receipt = self._effect(admission, admission.action("start", now=self.monotonic()),
                               timeout=timeout, cancelled=cancelled)
        process_id = self._process_id_from_receipt(receipt, admission)
        with self._lock:
            self._process_ids[handle] = process_id
        return receipt

    def status_selected_memory(self, handle: str, *, timeout: float = 10.0,
                               cancelled: Callable[[], bool] | None = None) -> Any:
        admission = self.resolve_admission(handle)
        with self._lock:
            process_id = self._process_ids.get(handle)
        if process_id is None:
            raise MemoryLifecycleDenied("memory service has no root-retained process start receipt")
        binding = admission.action("status", now=self.monotonic()).with_retained_process(process_id)
        return self._effect(admission, binding, timeout=timeout, cancelled=cancelled)

    def stop_selected_memory(self, handle: str, *, reason: str = "shutdown", timeout: float = 30.0,
                             cancelled: Callable[[], bool] | None = None) -> Any:
        admission = self.resolve_admission(handle)
        with self._lock:
            process_id = self._process_ids.get(handle)
        if process_id is None:
            raise MemoryLifecycleDenied("memory service has no root-retained process start receipt")
        binding = (admission.action("stop", now=self.monotonic(), reason=reason)
                   .with_retained_process(process_id))
        receipt = self._effect(admission, binding, timeout=timeout, cancelled=cancelled)
        with self._lock:
            self._process_ids.pop(handle, None)
            self._stopped.add(handle)
        return receipt

    def restart_selected_memory(self, handle: str, *, timeout: float = 60.0,
                                cancelled: Callable[[], bool] | None = None) -> tuple[Any, Any]:
        admission = self.resolve_admission(handle)
        life = admission._enrollment.lifecycle_binding
        assert life is not None
        with self._lock:
            used = self._restart_uses.get(handle, life.maximum_restart_attempts)
            if (life.restart_policy != "bounded-owned-restart"
                    or used >= life.maximum_restart_attempts):
                raise MemoryLifecycleDenied("selected memory restart quota or policy denies restart")
        stop_receipt = self.stop_selected_memory(handle, timeout=timeout, cancelled=cancelled)
        if not admission.is_current(now=self.monotonic()):
            raise MemoryLifecycleDenied("memory admission changed after stop; restart was not attempted")
        start_receipt = self.start_selected_memory(handle, timeout=timeout, cancelled=cancelled)
        return stop_receipt, start_receipt


def new_memory_admission_handle() -> str:
    """Generate a non-predictable in-process lookup handle for the root registry."""
    return secrets.token_urlsafe(32)
