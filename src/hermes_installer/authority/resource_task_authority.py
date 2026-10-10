"""One-use root authority for already-admitted resource profile tasks.

This authority is deliberately separate from ordinary worker grants and from
the selected-service lifecycle issuer.  It consumes only retained job records
and signs an exact process-start selection for a single admitted task attempt.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping

from .types import AuthorityDenied, Sensitivity, canonical_bytes


def _digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _opaque(value: Any) -> bool:
    return isinstance(value, str) and 32 <= len(value) <= 128 and all(
        c.isascii() and (c.isalnum() or c in "_-") for c in value
    )


def re_full_hex(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


@dataclass(frozen=True, slots=True)
class RootResourceTaskContext:
    schema: int
    context_id: str
    admission_handle: str
    admission_kind: str
    controller_proof_sha256: str
    selected_principal_id: str
    selected_profile_id: str
    selected_generation: str
    selected_namespace_identity: str
    selected_subject_uid: int
    selected_subject_gid: int
    service_generation_digest: str
    role: str
    action: str
    enrollment_id: str
    operation_id: str
    operation: str
    capability: str
    target: str
    source_closure_sha256: str
    sensitivity: Sensitivity
    recipient: str | None
    policy_revision: str
    authority_epoch: str
    issued_monotonic: float
    expires_monotonic: float
    nonce: str
    signature: str
    job_handle: str
    node_id: str
    child_admission_id: str
    retry_index: int
    task_payload_sha256: str
    stdin_sha256: str
    stdin_size_bytes: int

    def __post_init__(self) -> None:
        if (type(self.schema) is not int or self.schema != 1
                or not all(_opaque(getattr(self, name)) for name in (
                    "context_id", "admission_handle", "job_handle", "child_admission_id", "nonce"))
                or not all(isinstance(getattr(self, name), str) and 1 <= len(getattr(self, name)) <= 256
                           for name in ("node_id", "selected_principal_id", "selected_profile_id",
                                        "selected_generation", "selected_namespace_identity", "role",
                                        "action", "enrollment_id", "operation_id", "operation",
                                        "capability", "target", "policy_revision", "authority_epoch"))
                or self.admission_kind != "resource-child-task" or self.role != "resource-profile-task"
                or self.action != "start" or self.operation != "process.start"
                or not _digest(self.controller_proof_sha256) or not _digest(self.service_generation_digest)
                or not _digest(self.source_closure_sha256) or not _digest(self.task_payload_sha256)
                or not _digest(self.stdin_sha256) or type(self.retry_index) is not int
                or not 0 <= self.retry_index <= 9 or type(self.stdin_size_bytes) is not int
                or not 1 <= self.stdin_size_bytes <= 262_144
                or type(self.selected_subject_uid) is not int or self.selected_subject_uid <= 0
                or type(self.selected_subject_gid) is not int or self.selected_subject_gid < 0
                or not isinstance(self.sensitivity, Sensitivity) or self.sensitivity is Sensitivity.PUBLIC
                or self.recipient is not None and (not isinstance(self.recipient, str) or not self.recipient)
                or not _digest(self.signature) or not re_full_hex(self.nonce)
                or not math.isfinite(self.issued_monotonic) or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic
                or self.expires_monotonic - self.issued_monotonic > 30.0):
            raise AuthorityDenied("resource.task_context", "root resource task context is malformed")

    def claims(self) -> dict[str, Any]:
        result = {name: getattr(self, name) for name in self.__dataclass_fields__ if name not in {"signature", "sensitivity"}}
        result["sensitivity"] = self.sensitivity.value
        return result

    def to_wire(self) -> dict[str, Any]:
        return {**self.claims(), "signature": self.signature}

    @property
    def uid(self) -> int: return self.selected_subject_uid
    @property
    def profile_id(self) -> str: return self.selected_profile_id
    @property
    def principal_id(self) -> str: return self.selected_principal_id
    @property
    def namespace_id(self) -> str: return self.selected_namespace_identity
    @property
    def purpose(self) -> str: return "resource-profile-task"
    @property
    def intent_id(self) -> str: return self.context_id
    @property
    def trace_id(self) -> str: return self.context_id
    @property
    def lineage_hash(self) -> str: return self.source_closure_sha256
    @property
    def capabilities(self) -> frozenset[str]: return frozenset({self.capability})
    @property
    def final_payload_digest(self) -> str: return self.task_payload_sha256
    @property
    def issued_at_monotonic(self) -> float: return self.issued_monotonic
    @property
    def monotonic_expires_at(self) -> float: return self.expires_monotonic


@dataclass(frozen=True, slots=True)
class RootResourceTaskEffectAuthorization:
    schema: int
    grant_id: str
    context_sha256: str
    admission_handle: str
    operation: str
    capability: str
    target: str
    request_sha256: str
    nonce: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str

    def __post_init__(self) -> None:
        if (type(self.schema) is not int or self.schema != 1
                or not _opaque(self.grant_id) or not _opaque(self.admission_handle)
                or self.operation != "process.start" or not self.capability or not self.target
                or not all(_digest(value) for value in (self.context_sha256, self.request_sha256,
                                                        self.nonce, self.signature))
                or not math.isfinite(self.issued_monotonic) or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic
                or self.expires_monotonic - self.issued_monotonic > 30.0):
            raise AuthorityDenied("resource.task_grant", "root resource task grant is malformed")

    def claims(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__ if name != "signature"}

    def to_wire(self) -> dict[str, Any]:
        return {**self.claims(), "signature": self.signature}


@dataclass(frozen=True, slots=True)
class RootResourceTaskStartGrant:
    context: RootResourceTaskContext
    authorization: RootResourceTaskEffectAuthorization


@dataclass(frozen=True, slots=True)
class VerifiedRootResourceTaskStart:
    """Sealed in-process proof; signatures alone never make an effect usable."""

    context: RootResourceTaskContext
    authorization: RootResourceTaskEffectAuthorization
    selected_profile: Any = field(repr=False, compare=False)
    selected_home_binding: Any = field(repr=False, compare=False)
    _issuer: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)
    _nonce: str = field(repr=False, compare=False)


class RootResourceTaskAuthority:
    """AuthorityService-bound issuer and one-use verifier for RB-T08 starts."""

    def __init__(self, service: Any, jobs: Any, controller_registry: Any):
        self.service = service
        self.jobs = jobs
        self.controller_registry = controller_registry
        self._lock = threading.RLock()
        self._seal = object()
        self._grants: dict[str, dict[str, Any]] = {}
        self._nonces: dict[str, tuple[str, float]] = {}

    @classmethod
    def from_authority_service(cls, service: Any, resource_job_authority: Any,
                               controller_registry: Any) -> "RootResourceTaskAuthority":
        from .service import AuthorityService
        from .resource_jobs import ResourceJobAuthority
        from .resource_source_controllers import RootResourceControllerRegistry

        if (not isinstance(service, AuthorityService)
                or not isinstance(resource_job_authority, ResourceJobAuthority)
                or getattr(resource_job_authority, "service", None) is not service
                or type(controller_registry) is not RootResourceControllerRegistry
                or getattr(controller_registry, "service", None) is not service):
            raise AuthorityDenied("resource.task_authority", "root resource task authorities do not share one service")
        issuer = cls(service, resource_job_authority, controller_registry)
        service.attach_resource_task_authority(issuer)
        return issuer

    def issue_root_resource_task_start(
        self, child_admission: Any, task_source: Any, task_admission: Any,
        selected_execution: Any, *, task_handle: Any, controller: Any,
        selected_home_binding: Any,
    ) -> RootResourceTaskStartGrant:
        from hermes_installer.registry.resource_jobs import (
            ResourceChildAdmission, RootAdmittedTask, RootAdmittedTaskSource,
            RootResourceJobAdmissionHandle, RootTaskController,
        )
        from hermes_installer.registry.resource_backends import SelectedResourceProfileTask
        from .native_profile_task_homes import RootSelectedResourceTaskHomeBinding

        service = self.service
        if (not isinstance(task_handle, RootResourceJobAdmissionHandle)
                or not isinstance(child_admission, ResourceChildAdmission)
                or not isinstance(task_admission, RootAdmittedTask)
                or not isinstance(task_source, RootAdmittedTaskSource)
                or not isinstance(controller, RootTaskController)
                or not isinstance(selected_execution, SelectedResourceProfileTask)
                or type(selected_home_binding) is not RootSelectedResourceTaskHomeBinding
                or not selected_home_binding.verify_current(selected_execution)):
            raise AuthorityDenied("resource.task_start", "root task selection has an invalid type")
        if (not isinstance(task_source.sensitivity, Sensitivity)
                or task_source.sensitivity is Sensitivity.PUBLIC
                or not _digest(service.service_generation_digest)):
            raise AuthorityDenied("resource.task_start", "root task source sensitivity or service snapshot is invalid")
        current_child = self.jobs.resolve_task_child_admission(task_handle, task_handle.node_id)
        try:
            if (current_child is not child_admission
                    or not self.jobs.verify_admitted_root_task_controller(
                        task_handle, task_admission, task_source, controller)
                    or not self.jobs.is_admitted_task_current(task_admission)
                    or task_source.parent_closure_digest != task_handle.parent_closure_digest
                    or task_admission.parent_closure_digest != task_handle.parent_closure_digest
                    or selected_execution.resource_backend_id != task_handle.backend_enrollment_id
                    or selected_execution.resource_id != child_admission.resource_id
                    or selected_execution.resource_generation != child_admission.generation
                    or selected_execution.profile_id != task_handle.profile_id
                    or selected_execution.profile_generation != task_handle.profile_generation
                    or selected_execution.process_enrollment_id != task_handle.process_enrollment_id
                    or selected_execution.process_generation != task_handle.process_generation
                    or selected_execution.operation_id != task_handle.operation_id
                    or selected_execution.process_start_target != task_handle.child_target_id
                    or selected_execution.native_package_id != task_handle.native_package_id
                    or selected_execution.native_package_generation != task_handle.native_package_generation
                    or selected_execution.task_body_recipe_id != task_handle.task_body_recipe_id
                    or selected_execution.task_request_schema_id != task_handle.task_request_schema_id
                    or selected_execution.source_profile_id != selected_home_binding.source_profile_id
                    or selected_execution.home_binding_id != selected_home_binding.home_binding_id
                    or service.monotonic() >= min(task_handle.expires_monotonic, task_admission.deadline_monotonic,
                                                  task_source.expires_monotonic, controller.expires_monotonic)):
                raise AuthorityDenied("resource.task_start", "retained child, controller or selected execution changed")
            profile = getattr(service.process_effect_handler, "profiles", {}).get(selected_execution.profile_id)
            resolve_selected_operation = service.selected_operation_resolver
            protected_operation = (resolve_selected_operation(
                task_handle.process_enrollment_id, task_handle.process_generation,
                "process.start", task_handle.operation_id,
            ) if callable(resolve_selected_operation) else None)
            if (profile is None or profile.profile_id != selected_execution.profile_id
                    or profile.generation != selected_execution.profile_generation
                    or profile.enrollment_id != selected_execution.process_enrollment_id
                    or profile.operation_targets is None
                    or profile.operation_targets.get("process.start") != selected_execution.process_start_target
                    or protected_operation is None
                    or getattr(protected_operation, "target", None) != selected_execution.process_start_target
                    or getattr(protected_operation, "profile_id", None) != profile.profile_id
                    or getattr(protected_operation, "generation", None) != profile.generation
                    or getattr(protected_operation, "enrollment_id", None) != profile.enrollment_id):
                raise AuthorityDenied("resource.task_start", "selected process profile is no longer current")
            payload = self.selection_payload(task_handle, task_admission, selected_execution, profile,
                                              selected_home_binding)
            request_sha = hashlib.sha256(payload).hexdigest()
            now = service.monotonic()
            expiry = min(float(task_handle.expires_monotonic), float(task_admission.deadline_monotonic),
                         float(task_source.expires_monotonic), float(controller.expires_monotonic), now + 30.0)
            if expiry <= now:
                raise AuthorityDenied("resource.task_start", "root task start lease expired")
            binding = next((item for item in service.bindings_by_uid.values()
                            if item.profile_id == profile.profile_id), None)
            if binding is None or binding.uid != profile.owner_uid:
                raise AuthorityDenied("resource.task_start", "selected process principal is not enrolled")
            rule = service.rules.get((task_handle.child_capability, "process.start", task_handle.child_target_id))
            if rule is None or rule.recipient != child_admission.recipient:
                raise AuthorityDenied("resource.task_start", "exact selected process.start rule is absent")
            controller_digest = hashlib.sha256(canonical_bytes({
                "kind": controller.controller_kind,
                "role_artifact_id": controller.controller_role_artifact_id,
                "role_sha256": controller.controller_role_sha256,
                "pid": controller.pid, "uid": controller.uid,
                "identity": repr(controller.identity),
                "generation": controller.controller_generation,
                "source_receipt_id": controller.source_receipt_id,
            })).hexdigest()
            fields = {
                "schema": 1, "context_id": secrets.token_urlsafe(32),
                "admission_handle": task_handle.handle_id, "admission_kind": "resource-child-task",
                "controller_proof_sha256": controller_digest,
                "selected_principal_id": binding.principal_id,
                "selected_profile_id": profile.profile_id, "selected_generation": profile.generation,
                "selected_namespace_identity": binding.namespace_id,
                "selected_subject_uid": profile.owner_uid, "selected_subject_gid": profile.owner_gid,
                "service_generation_digest": service.service_generation_digest,
                "role": "resource-profile-task", "action": "start",
                "enrollment_id": profile.enrollment_id, "operation_id": selected_execution.operation_id,
                "operation": "process.start", "capability": task_handle.child_capability,
                "target": task_handle.child_target_id,
                "source_closure_sha256": task_source.parent_closure_digest,
                "sensitivity": task_source.sensitivity, "recipient": rule.recipient,
                "policy_revision": service._policy_revision(), "authority_epoch": service.authority_epoch,
                "issued_monotonic": now, "expires_monotonic": expiry, "nonce": secrets.token_hex(32),
                "job_handle": task_handle.handle_id, "node_id": task_handle.node_id,
                "child_admission_id": task_handle.child_admission_id,
                "retry_index": task_handle.attempt_index,
                "task_payload_sha256": task_handle.task_payload_sha256,
                "stdin_sha256": task_admission.stdin_sha256,
                "stdin_size_bytes": task_admission.stdin_size_bytes,
            }
            signed_context_fields = {**fields, "sensitivity": task_source.sensitivity.value}
            context = RootResourceTaskContext(**fields, signature=service._sign_root_selected(
                "root-resource-task-context-v1", signed_context_fields))
            context_sha = hashlib.sha256(canonical_bytes(context.to_wire())).hexdigest()
            nonce = secrets.token_hex(32)
            grant_fields = {
                "schema": 1, "grant_id": secrets.token_urlsafe(32), "context_sha256": context_sha,
                "admission_handle": task_handle.handle_id, "operation": "process.start",
                "capability": task_handle.child_capability, "target": task_handle.child_target_id,
                "request_sha256": request_sha, "nonce": nonce,
                "issued_monotonic": now, "expires_monotonic": expiry,
            }
            auth = RootResourceTaskEffectAuthorization(**grant_fields, signature=service._sign_root_selected(
                "root-resource-task-effect-v1", grant_fields))
            if not service.policy.allow_effect(context=context, rule=rule,
                                               request_digest=request_sha,
                                               retry_index=child_admission.retry_index):
                raise AuthorityDenied("resource.task_start", "current policy denied selected resource task")
            with self._lock:
                self._prune(now)
                if nonce in self._nonces or len(self._grants) >= 10_000:
                    raise AuthorityDenied("resource.task_start", "root task nonce registry is full")
                self._nonces[nonce] = ("pending", expiry)
                self._grants[auth.grant_id] = {
                    "grant": auth, "context": context, "handle": task_handle,
                    "child": child_admission, "source": task_source, "task": task_admission,
                    "execution": selected_execution, "controller_digest": controller_digest,
                    "home_binding": selected_home_binding,
                    "controller": controller,
                    "profile": profile, "selection_payload": payload,
                    "state": "pending", "proof": None,
                }
            return RootResourceTaskStartGrant(context, auth)
        finally:
            # The task runner owns the already-resolved controller PIDFD and
            # keeps it live through launch and terminal reconciliation.
            pass

    def consume_root_resource_task_start(
        self, grant: RootResourceTaskStartGrant, child_admission: Any, task_source: Any,
        task_admission: Any, canonical_selection_payload: bytes, *, task_handle: Any,
    ) -> VerifiedRootResourceTaskStart:
        service = self.service
        if type(grant) is not RootResourceTaskStartGrant or not isinstance(canonical_selection_payload, bytes):
            raise AuthorityDenied("resource.task_start", "root task grant is malformed")
        auth, context = grant.authorization, grant.context
        self._verify("root-resource-task-effect-v1", auth.claims(), auth.signature)
        payload_sha = hashlib.sha256(canonical_selection_payload).hexdigest()
        now = service.monotonic()
        with self._lock:
            self._prune(now)
            entry = self._grants.get(auth.grant_id)
            if (entry is None or entry["grant"] is not auth or entry["context"] is not context
                    or entry["state"] != "pending" or entry["handle"] is not task_handle
                    or entry["child"] is not child_admission or entry["source"] is not task_source
                    or entry["task"] is not task_admission or auth.request_sha256 != payload_sha
                    or entry["selection_payload"] != canonical_selection_payload
                    or auth.expires_monotonic <= now
                    or self._nonces.get(auth.nonce) != ("pending", auth.expires_monotonic)):
                raise AuthorityDenied("resource.task_start", "root task grant is stale, mismatched or spent")
            self._verify("root-resource-task-context-v1", context.claims(), context.signature)
            expected_context_sha = hashlib.sha256(canonical_bytes(context.to_wire())).hexdigest()
            if not hmac.compare_digest(expected_context_sha, auth.context_sha256):
                raise AuthorityDenied("resource.task_start", "root task context digest is invalid")
            current_child = self.jobs.resolve_task_child_admission(task_handle, task_handle.node_id)
            controller = entry["controller"]
            if (current_child is not child_admission
                        or not self.jobs.verify_admitted_root_task_controller(task_handle, task_admission,
                                                                             task_source, controller)
                        or not self.jobs.is_admitted_task_current(task_admission, canonical_selection_payload)
                        or not self.jobs.is_admitted_task_controller_current(
                            task_handle, task_handle.node_id, controller)
                        or not self._controller_matches_digest(controller, entry["controller_digest"])
                        or not self._context_matches(context, task_handle, task_source, task_admission,
                                                     entry["execution"], entry["profile"])
                    or not self._is_current(entry)):
                raise AuthorityDenied("resource.task_start", "root task source or controller changed")
            self._nonces[auth.nonce] = ("consumed", auth.expires_monotonic)
            proof = VerifiedRootResourceTaskStart(context, auth, entry["profile"],
                                                  entry["home_binding"], self, self._seal, auth.nonce)
            entry["state"], entry["proof"] = "consumed", proof
            return proof

    def verify_consumed_start(self, proof: VerifiedRootResourceTaskStart,
                              canonical_selection_payload: bytes, *, task_admission: Any,
                              selected_profile: Any) -> bool:
        if type(proof) is not VerifiedRootResourceTaskStart or proof._issuer is not self or proof._seal is not self._seal:
            return False
        with self._lock:
            entry = self._grants.get(proof.authorization.grant_id)
            if (entry is None or entry["proof"] is not proof or entry["state"] != "consumed"
                    or entry["task"] is not task_admission or entry["profile"] is not selected_profile
                    or proof.selected_profile is not selected_profile
                    or proof.selected_home_binding is not entry["home_binding"]
                    or proof.authorization.request_sha256 != hashlib.sha256(canonical_selection_payload).hexdigest()
                    or self._nonces.get(proof._nonce) != ("consumed", proof.authorization.expires_monotonic)):
                return False
            return self._is_current(entry)

    def _is_current(self, entry: Mapping[str, Any]) -> bool:
        handle, task, context = entry["handle"], entry["task"], entry["context"]
        try:
            return (self.service.monotonic() < entry["grant"].expires_monotonic
                    and self.jobs.resolve_task_child_admission(handle, handle.node_id) is entry["child"]
                    and self.jobs.is_admitted_task_current(task, entry["selection_payload"])
                    and context.authority_epoch == self.service.authority_epoch
                    and context.service_generation_digest == self.service.service_generation_digest
                    and context.policy_revision == self.service._policy_revision()
                    and context.selected_generation == self.service.profile_generations.get(context.selected_profile_id)
                    and self._controller_is_current(handle, entry)
                    and entry["home_binding"].verify_current(entry["execution"]))
        except Exception:
            return False

    def _controller_is_current(self, handle: Any, entry: Mapping[str, Any]) -> bool:
        controller = entry["controller"]
        return (self.jobs.is_admitted_task_controller_current(handle, handle.node_id, controller)
                    and self.jobs.verify_admitted_root_task_controller(
                        handle, entry["task"], entry["source"], controller)
                    and self._controller_matches_digest(controller, entry["controller_digest"]))

    @staticmethod
    def selection_payload(handle: Any, task: Any, execution: Any, profile: Any,
                          selected_home_binding: Any) -> bytes:
        return canonical_bytes({
            "schema": 1, "enrollment_id": profile.enrollment_id, "generation": profile.generation,
            "operation_id": execution.operation_id, "parameters": {},
            "admission_handle": handle.handle_id, "node_id": handle.node_id,
            "task_payload_sha256": handle.task_payload_sha256,
            "stdin_sha256": task.stdin_sha256, "stdin_size_bytes": task.stdin_size_bytes,
            "source_profile_id": execution.source_profile_id,
            "home_binding_id": execution.home_binding_id,
            "home_binding_handle": selected_home_binding.binding_handle,
            "home_binding_sha256": selected_home_binding.binding_sha256,
        })

    @staticmethod
    def _context_matches(context: RootResourceTaskContext, handle: Any, source: Any,
                         task: Any, execution: Any, profile: Any) -> bool:
        return (context.admission_handle == handle.handle_id and context.job_handle == handle.handle_id
                and context.node_id == handle.node_id and context.child_admission_id == handle.child_admission_id
                and context.retry_index == handle.attempt_index
                and context.task_payload_sha256 == handle.task_payload_sha256
                and context.stdin_sha256 == task.stdin_sha256
                and context.stdin_size_bytes == task.stdin_size_bytes
                and context.source_closure_sha256 == source.parent_closure_digest
                and context.selected_profile_id == profile.profile_id
                and context.selected_generation == profile.generation
                and context.selected_principal_id == profile.principal_id
                and context.selected_subject_uid == profile.owner_uid
                and context.selected_subject_gid == profile.owner_gid
                and context.enrollment_id == profile.enrollment_id
                and context.target == handle.child_target_id and context.operation == "process.start"
                and context.operation_id == execution.operation_id)

    @staticmethod
    def _controller_matches_digest(controller: Any, expected: str) -> bool:
        actual = hashlib.sha256(canonical_bytes({
            "kind": controller.controller_kind,
            "role_artifact_id": controller.controller_role_artifact_id,
            "role_sha256": controller.controller_role_sha256,
            "pid": controller.pid, "uid": controller.uid,
            "identity": repr(controller.identity), "generation": controller.controller_generation,
            "source_receipt_id": controller.source_receipt_id,
        })).hexdigest()
        return hmac.compare_digest(actual, expected)

    def _verify(self, domain: str, claims: Mapping[str, Any], signature: str) -> None:
        self.service._verify_root_selected_signature(domain, claims, signature)

    def _prune(self, now: float) -> None:
        for key, entry in tuple(self._grants.items()):
            if entry["grant"].expires_monotonic <= now:
                self._grants.pop(key, None)
        for nonce, (_state, expiry) in tuple(self._nonces.items()):
            if expiry <= now:
                self._nonces.pop(nonce, None)
