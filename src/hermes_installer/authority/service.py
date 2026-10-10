"""Root-owned signing, peer binding and one-use fixed-verb authority service.

The caller never chooses its UID, profile, namespace or principal. The service
reads SO_PEERCRED, resolves a protected binding, signs short claims with a key
that remains in this process, and independently checks/consumes every grant.
Effect handlers are explicit reviewed adapters keyed by fixed operation and
protected target IDs; this is not a URL proxy or shell interface.
"""
from __future__ import annotations

import hashlib
import hmac
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
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .types import (
    AuthorityDenied, BrokeredEffectResponse, EffectAuthorization, HostContext, Sensitivity, SourceReceipt,
    canonical_bytes, canonical_digest, strict_json_loads,
)

MAX_REQUEST = 4 * 1024 * 1024 + 16_384
MAX_RESPONSE = 4 * 1024 * 1024 + 32_768
MAX_CONTEXT_LEASE = 600.0
MAX_EFFECT_LEASE = 30.0
_EFFECT_LEASE_BY_OPERATION = {
    "artifact.fetch": 120.0,
    "package.install": 600.0,
    "process.start": 30.0,
}
_OPERATIONS = frozenset({
    "provider.dispatch", "mcp.request", "mcp.stdio", "memory.request", "memory.doctor",
    "memory.capture", "memory.search", "memory.export", "memory.delete",
    "memory.extract", "memory.embed", "memory.backup", "memory.restore",
    "memory.enqueue", "memory.result",
    "host.write", "alert.deliver", "plugin.agent-live-wallet.execute",
    "plugin.agent-live-wallet.read", "plugin.agent-sandbox-wallet.execute",
    "plugin.agent-sandbox-wallet.read", "plugin.authentik-authorization.read",
    "plugin.cloudflare-homelab.read", "plugin.cloudflare-homelab.write",
    "plugin.codex.run", "plugin.composio.invoke", "plugin.ebook-toolchain.run",
    "plugin.epic-kanban.delete", "plugin.epic-kanban.read", "plugin.epic-kanban.write",
    "plugin.financial-data-hub.read", "plugin.financial-execution-gateway.execute",
    "plugin.github.admin", "plugin.github.read", "plugin.github.write",
    "plugin.homelab-ops-broker.read", "plugin.homelab-ops-broker.write",
    "plugin.kobo-bridge.deliver", "plugin.kobo-bridge.read",
    "plugin.resource-overlay-store.backup", "plugin.resource-overlay-store.read",
    "plugin.resource-overlay-store.write", "plugin.voice-pipeline.session",
    "plugin.voice-pipeline.stt", "plugin.voice-pipeline.tts", "plugin.web.read",
    "process.start", "process.status",
    "process.read", "process.write", "process.stop", "artifact.fetch", "package.install",
    "resource.cron.run", "resource.channel.route", "resource.webhook.deliver",
    "resource.webhook.run", "resource.channel.run", "resource.bundle.node.run",
    "resource.job.admit", "resource.job.child.admit",
    "resource.orchestrator.recruit",
    "process.inspect", "connector.open", "connector.read",
    "connector.write", "connector.close", "native.event.prepare", "native.request.dispatch",
})


@dataclass(frozen=True, slots=True)
class PrincipalBinding:
    uid: int
    principal_id: str
    profile_id: str
    namespace_id: str
    capabilities: frozenset[str]

    def __post_init__(self) -> None:
        if type(self.uid) is not int or self.uid <= 0 or not self.principal_id or not self.profile_id or not self.namespace_id:
            raise ValueError("protected principal binding is incomplete")
        if not self.capabilities or any(not isinstance(cap, str) or not cap for cap in self.capabilities):
            raise ValueError("protected principal capabilities are required")


@dataclass(frozen=True, slots=True)
class EffectRule:
    capability: str
    operation: str
    target: str
    recipient: str | None = None

    def __post_init__(self) -> None:
        if self.operation not in _OPERATIONS or not self.capability or not self.target:
            raise ValueError("effect rule must name a fixed operation, capability and target")


@dataclass(frozen=True, slots=True)
class ChildDelegationRule:
    """One fixed root-only parent action to one fixed child effect."""

    delegation_id: str
    parent_profile_id: str
    parent_capability: str
    parent_operation: str
    parent_target: str
    child_profile_id: str
    child_capability: str
    child_operation: str
    child_target: str
    child_recipient: str | None
    child_purpose: str

    def __post_init__(self) -> None:
        if (not self.delegation_id or not self.parent_profile_id or not self.parent_capability
                or not self.parent_operation or not self.parent_target or not self.child_profile_id
                or not self.child_capability or not self.child_operation or not self.child_target
                or not self.child_purpose):
            raise ValueError("child delegation binding is incomplete")


@dataclass(frozen=True, slots=True)
class BackgroundConsent:
    """Root-signed durable provenance permission, distinct from an effect grant."""

    claims: Mapping[str, Any]
    signature: str

    def to_wire(self) -> dict[str, Any]:
        return {**dict(self.claims), "signature": self.signature}


class AuthorityPolicy(Protocol):
    def classify(self, *, purpose: str, intent: str,
                 source_contexts: tuple[HostContext, ...],
                 binding: PrincipalBinding) -> tuple[Sensitivity, str]: ...

    def allow_effect(self, *, context: HostContext, rule: EffectRule,
                     request_digest: str, retry_index: int) -> bool: ...


class EffectHandler(Protocol):
    def __call__(self, *, context: HostContext, authorization: EffectAuthorization,
                 payload: bytes, timeout: float,
                 peer_pid: int,
                 peer_pidfd: int | None,
                 cancelled: Callable[[], bool]) -> Mapping[str, Any]: ...


class DenyByDefaultPolicy:
    """Safe policy until protected purpose/capability rules are enrolled."""

    def classify(self, *, purpose: str, intent: str,
                 source_contexts: tuple[HostContext, ...],
                 binding: PrincipalBinding) -> tuple[Sensitivity, str]:
        if source_contexts:
            sensitivity = max((source.sensitivity for source in source_contexts), key=lambda item: list(Sensitivity).index(item))
            lineage = canonical_digest(sorted(_context_digest(source) for source in source_contexts))
            return sensitivity, lineage
        # An empty source list is unknown; never assume public from caller text.
        return Sensitivity.UNKNOWN, canonical_digest({"empty": True, "purpose": purpose})

    def allow_effect(self, *, context: HostContext, rule: EffectRule,
                     request_digest: str, retry_index: int) -> bool:
        return False


def _context_digest(context: HostContext) -> str:
    return canonical_digest({**context.claims(), "signature": context.signature})


class AuthorityService:
    """One authenticated client request per connection on the fixed socket."""

    def __init__(self, *, signing_key: bytes, key_id: str,
                 bindings_by_uid: Mapping[int, PrincipalBinding],
                 rules: Mapping[tuple[str, str, str], EffectRule],
                 handlers: Mapping[tuple[str, str], EffectHandler],
                 policy: AuthorityPolicy | None = None,
                 monotonic: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time,
                 profile_generations: Mapping[str, str] | None = None,
                 background_consent_active: Callable[[str], bool] | None = None,
                 delegations: Mapping[str, ChildDelegationRule] | None = None,
                 process_effect_handler: Any | None = None,
                 selected_operation_resolver: Callable[[str, str, str, str], Any] | None = None,
                 remote_session_authority: Any | None = None,
                 source_receipt_delivery: Any | None = None,
                 source_observer_registry: Any | None = None,
                 native_runtime_observer: Any | None = None,
                 native_invocation_registry: Any | None = None,
                 memory_step_effect_authority: Any | None = None,
                 service_generation_digest: str | None = None):
        if len(signing_key) < 32 or not key_id:
            raise ValueError("authority signing key must be protected and at least 256 bits")
        if not bindings_by_uid or any(uid != binding.uid for uid, binding in bindings_by_uid.items()):
            raise ValueError("UID map must be an explicit protected identity mapping")
        profile_ids = [binding.profile_id for binding in bindings_by_uid.values()]
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("each managed profile must map to exactly one host principal UID")
        if any(key != (rule.capability, rule.operation, rule.target) for key, rule in rules.items()):
            raise ValueError("effect rule map keys must match their protected rule bindings")
        enrolled_operations = {(rule.operation, rule.target) for rule in rules.values()}
        if set(handlers) - enrolled_operations:
            raise ValueError("effect handler has no protected enrollment rule")
        self._key = bytes(signing_key)
        self.key_id = key_id
        self.bindings_by_uid = dict(bindings_by_uid)
        self.rules = dict(rules)
        self.handlers = dict(handlers)
        self.policy = policy or DenyByDefaultPolicy()
        self.monotonic = monotonic
        self.wall_clock = wall_clock
        self.profile_generations = dict(profile_generations or {})
        # Bind every context/receipt/grant to this daemon epoch. The signing
        # key intentionally survives service restarts, but replay tables do
        # not; changing this host-derived enrollment digest makes old signed
        # effects stale before they can reach a handler after restart.
        self.authority_epoch = secrets.token_urlsafe(24)
        self.delegations = dict(delegations or {})
        self.process_effect_handler = process_effect_handler
        self.native_bridge_broker = None
        self.selected_operation_resolver = selected_operation_resolver
        self.remote_session_authority = remote_session_authority
        self.source_receipt_delivery = source_receipt_delivery
        self.source_observer_registry = source_observer_registry
        self.native_runtime_observer = native_runtime_observer
        self.native_invocation_registry = native_invocation_registry
        self.native_input_delivery_registry = None
        self.native_turn_observation_registry = None
        self.native_mcp_dispatcher = None
        self.memory_step_effect_authority = memory_step_effect_authority
        self.resource_task_runner = None
        self.resource_job_authority = None
        self.resource_event_context_issuer = None
        if (service_generation_digest is not None
                and not re.fullmatch(r"[0-9a-f]{64}", service_generation_digest)):
            raise ValueError("active service generation digest is invalid")
        self.service_generation_digest = service_generation_digest
        if any(key != rule.delegation_id for key, rule in self.delegations.items()):
            raise ValueError("delegation map keys must match fixed enrollment IDs")
        self._delegated_parents: set[str] = set()
        # Queue adapters must supply a durable root-owned revocation lookup.
        self.background_consent_active = background_consent_active or (lambda _consent_id: False)
        self.memory_owner_state: Callable[[str], tuple[str | None, int]] | None = None
        self._nonces: dict[str, float] = {}
        # Receipts are provenance evidence, not reusable bearer permissions.
        # Consumption is atomic with the one-use effect nonce below.
        self._source_receipts_consumed: dict[str, float] = {}
        self._source_receipt_handles: dict[str, SourceReceipt] = {}
        self._observed_event_ids: set[str] = set()
        self._lock = threading.RLock()
        self._client_nonces: dict[str, float] = {}

    def attach_source_observer_registry(self, registry: Any) -> None:
        """Attach one root-built source registry after service construction.

        Registry construction needs the service's epoch and signing methods,
        so daemon assembly constructs the service first and then attaches the
        strict protected registry exactly once.
        """
        if (self.source_observer_registry is not None
                or getattr(registry, "service", None) is not self
                or not callable(getattr(registry, "consume_observation_proof", None))):
            raise AuthorityDenied("source.enrollment", "root source observer registry binding is invalid")
        self.source_observer_registry = registry
        if self.source_receipt_delivery is None and callable(getattr(registry, "take_source_receipt", None)):
            self.source_receipt_delivery = registry

    def revoke_source_handle(self, handle: Any) -> bool:
        """Revoke and scrub one root-retained source handle in-process only.

        This is used by root input/task coordinators when delivery or startup
        fails. It is deliberately not part of the worker RPC surface.
        """
        from .source_observers import SourceObserverRegistry, SourceReceiptHandle

        registry = self.source_observer_registry
        revoke = getattr(registry, "revoke_source_handle", None)
        if (type(handle) is not SourceReceiptHandle
                or type(registry) is not SourceObserverRegistry
                or not callable(revoke)):
            raise AuthorityDenied("source.capsule", "root source handle revocation is unavailable")
        return revoke(handle)

    def resolve_retained_source_receipt(
        self, handle: Any, *, payload_digest: str,
        profile_id: str | None = None, generation: str | None = None,
    ) -> SourceReceipt:
        """Resolve a root-retained receipt for another protected root verifier.

        This is an in-process integrity check, not an RPC or receipt minting
        API. Callers must already hold the opaque handle from a protected
        registry; the exact stored, signed receipt is returned only if its
        payload and any requested identity pins match.
        """
        from .source_observers import SourceReceiptHandle

        if (type(handle) is not SourceReceiptHandle
                or not isinstance(payload_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", payload_digest)
                or profile_id is not None and (not isinstance(profile_id, str) or not profile_id)
                or generation is not None and (not isinstance(generation, str) or not generation)):
            raise AuthorityDenied("source.receipt", "root retained receipt lookup is malformed")
        with self._lock:
            receipt = self._source_receipt_handles.get(str(handle))
            if receipt is None:
                raise AuthorityDenied("source.receipt", "root retained source receipt is unavailable")
            if (receipt.payload_digest != payload_digest
                    or profile_id is not None and receipt.profile_id != profile_id
                    or generation is not None and receipt.process_generation != generation):
                raise AuthorityDenied("source.receipt", "root retained source receipt binding does not match")
            self._verify_source_receipt(receipt, self._binding(receipt.uid))
            return receipt

    def attach_native_runtime_observer(self, observer: Any) -> None:
        """Attach the root-only post-effect observer exactly once after loading.

        The observer itself must be built from selected effect and source
        enrollments; no worker RPC can install or select observer IDs.
        """
        if (self.native_runtime_observer is not None
                or not callable(getattr(observer, "observe_effect_result", None))
                or not isinstance(getattr(observer, "effect_observer_ids", None), Mapping)):
            raise AuthorityDenied("source.observer", "root native result observer binding is invalid")
        self.native_runtime_observer = observer

    def attach_native_invocation_registry(self, registry: Any) -> None:
        """Attach the root-built observed-call registry once during startup."""
        if (self.native_invocation_registry is not None
                or not callable(getattr(registry, "begin_native_invocation", None))
                or not callable(getattr(registry, "get_invocation_contexts", None))
                or not callable(getattr(registry, "take_native_response_metadata", None))):
            raise AuthorityDenied("native.invocation", "root invocation registry binding is invalid")
        self.native_invocation_registry = registry

    def attach_native_bridge_broker(self, broker: Any) -> None:
        """Attach the one root-built native provider broker after registries exist."""
        from .native_bridge import NativeBridgeBroker

        if (self.native_bridge_broker is not None
                or not isinstance(broker, NativeBridgeBroker)
                or broker.service is not self
                or self.process_effect_handler is None
                or not isinstance(broker.bridges, Mapping) or not broker.bridges
                or set(broker.root_selected_enrollments) != set(broker.bridges)
                or broker.provider_response_registry is None
                or broker.provider_response_registry is not self.native_invocation_registry
                or not callable(broker.process_resolver)
                or not callable(broker.canonicalizer)
                or not re.fullmatch(r"[0-9a-f]{64}", broker.canonicalizer_sha256)):
            raise AuthorityDenied("native.broker", "root native bridge broker binding is invalid")
        self.native_bridge_broker = broker

    def attach_native_mcp_dispatcher(self, dispatcher: Any) -> None:
        """Attach the fixed root MCP dispatcher; it is never exposed as generic RPC."""
        if (self.native_mcp_dispatcher is not None
                or getattr(dispatcher, "service", None) is not self
                or not callable(getattr(dispatcher, "dispatch_native_mcp", None))):
            raise AuthorityDenied("native.mcp", "root native MCP dispatcher binding is invalid")
        self.native_mcp_dispatcher = dispatcher

    def attach_native_input_delivery_registry(self, registry: Any) -> None:
        """Attach the fixed selected-input queue/consumer once during assembly."""
        from .source_observers import RootNativeInputDeliveryRegistry

        if (self.native_input_delivery_registry is not None
                or type(registry) is not RootNativeInputDeliveryRegistry
                or getattr(registry, "service", None) is not self
                or not callable(getattr(registry, "take_selected_native_input", None))):
            raise AuthorityDenied("native.input.take", "root selected input delivery registry is invalid")
        self.native_input_delivery_registry = registry

    def attach_native_turn_observation_registry(self, registry: Any) -> None:
        """Attach the exact root-native turn observer once during assembly."""
        from .native_turn_observation import RootNativeTurnObservationRegistry

        if (self.native_turn_observation_registry is not None
                or type(registry) is not RootNativeTurnObservationRegistry
                or getattr(registry, "service", None) is not self
                or not callable(getattr(registry, "finish_selected_native_turn", None))):
            raise AuthorityDenied("native.turn.finish", "root native turn registry binding is invalid")
        self.native_turn_observation_registry = registry

    def attach_memory_step_effect_authority(self, authority: Any) -> None:
        """Attach the root-only memory compound step issuer exactly once."""
        if (self.memory_step_effect_authority is not None
                or not callable(getattr(authority, "perform_memory_connector_step", None))):
            raise AuthorityDenied("memory.step", "root memory step authority binding is invalid")
        self.memory_step_effect_authority = authority

    def attach_resource_task_runtime(self, runner: Any, job_authority: Any) -> None:
        """Attach the reviewed root task runner and its exact admission authority once."""
        from .resource_jobs import ResourceJobAuthority
        from .resource_task_execution import RootResourceTaskRunner

        if (self.resource_task_runner is not None or self.resource_job_authority is not None
                or not isinstance(job_authority, ResourceJobAuthority)
                or not isinstance(runner, RootResourceTaskRunner)
                or runner.service is not self or runner.jobs is not job_authority
                or job_authority.service is not self
                or getattr(runner, "manager", None) is not self.process_effect_handler):
            raise AuthorityDenied("resource.task", "root resource task runtime binding is invalid")
        current_admission = getattr(job_authority, "is_admitted_task_current", None)
        manager_current = getattr(self.process_effect_handler, "task_admission_current", None)
        if (not callable(current_admission)
                or manager_current not in (None, current_admission)):
            raise AuthorityDenied("resource.task", "root task admission verifier is unavailable")
        self.process_effect_handler.task_admission_current = current_admission
        self.resource_task_runner = runner
        self.resource_job_authority = job_authority

    def attach_resource_event_context_issuer(self, issuer: Any) -> None:
        """Attach the root source-event context issuer once during assembly."""
        from .resource_event_issuance import ResourceEventContextIssuer

        if (self.resource_event_context_issuer is not None
                or not isinstance(issuer, ResourceEventContextIssuer)
                or issuer.service is not self
                or getattr(issuer.controller_registry, "service", None) is not self):
            raise AuthorityDenied("resource.context", "root resource event issuer binding is invalid")
        self.resource_event_context_issuer = issuer

    def issue_resource_job_context(self, request: Any) -> tuple[HostContext, EffectAuthorization]:
        """Root-only in-process issuance for one registered source event and DAG node.

        This method is intentionally absent from the worker RPC operation table.
        The concrete issuer consumes the controller registry's instance-scoped
        request capability and independently revalidates the source, selected
        node, controller, current consent, and canonical effect bytes.
        """
        from .resource_event_issuance import ResourceEventContextIssuer
        from .resource_source_controllers import RootResourceJobContextRequest

        issuer = self.resource_event_context_issuer
        if (not isinstance(issuer, ResourceEventContextIssuer)
                or not isinstance(request, RootResourceJobContextRequest)
                or issuer.service is not self):
            raise AuthorityDenied("resource.context", "root resource event context issuer is unavailable")
        context, authorization = issuer.issue(request)
        if (not isinstance(context, HostContext)
                or not isinstance(authorization, EffectAuthorization)):
            raise AuthorityDenied("resource.context", "root resource event issuer returned invalid authority")
        binding = self._binding(context.uid)
        self._verify_context_signature(context)
        self._assert_current_context(context, binding, context.uid)
        self._verify_grant_signature(authorization)
        self._assert_grant_current(authorization, binding, authorization.uid)
        rule = self.rules.get(("hermes-resource-runtime", request.operation,
                               request.node.target))
        if (context.operation != request.operation
                or context.final_payload_digest != request.canonical_payload_sha256
                or context.source_receipts
                or authorization.operation != request.operation
                or authorization.capability != "hermes-resource-runtime"
                or authorization.target != request.node.target
                or authorization.recipient != request.node.recipient
                or authorization.request_digest != request.canonical_payload_sha256
                or authorization.final_payload_digest != request.canonical_payload_sha256
                or authorization.context_digest != _context_digest(context)
                or authorization.source_receipts
                or rule is None or rule.recipient != request.node.recipient):
            raise AuthorityDenied("resource.context", "issued resource effect does not match its consumed event request")
        return context, authorization

    def launch_resource_profile_task(self, admission_handle: Any, node_id: str) -> Any:
        """Root-private launch; worker RPC never accepts a task admission handle."""
        from hermes_installer.registry.resource_jobs import RootResourceJobAdmissionHandle

        runner = self.resource_task_runner
        if (runner is None or not isinstance(admission_handle, RootResourceJobAdmissionHandle)
                or not isinstance(node_id, str) or not node_id
                or node_id != admission_handle.node_id
                or not self.monotonic() < admission_handle.expires_monotonic):
            raise AuthorityDenied("resource.task", "selected root task runner is unavailable or admission is stale")
        return runner.launch_resource_profile_task(admission_handle, node_id)

    def perform_admitted_resource_process_start(
        self, admission: Any, task: Any, source: Any, controller: Any, selection: Any,
        *, exact_stdin: bytes, timeout: float, cancelled: Callable[[], bool],
    ) -> Any:
        """Mint and consume one reduced process.start grant for a root task.

        This fixed in-process seam is called only by ``RootResourceTaskRunner``.
        It re-resolves the original signed source context and live controller,
        derives the selected process target from protected enrollment, and
        consumes a fresh child grant before custody writes the admitted stdin.
        Parent receipts remain in the runner's private result lineage; they are
        not replayed as child-profile bearer receipts.
        """
        from hermes_installer.managed_process_custodian import ManagedTaskHandle
        from hermes_installer.registry.resource_jobs import (
            RootAdmittedTask, RootAdmittedTaskSource, RootResourceJobAdmissionHandle,
            RootTaskController,
        )
        from hermes_installer.registry.resource_backends import SelectedResourceProfileTask

        jobs = self.resource_job_authority
        manager = self.process_effect_handler
        if (jobs is None or self.resource_task_runner is None
                or not isinstance(admission, RootResourceJobAdmissionHandle)
                or not isinstance(task, RootAdmittedTask)
                or not isinstance(source, RootAdmittedTaskSource)
                or not isinstance(controller, RootTaskController)
                or not isinstance(selection, SelectedResourceProfileTask)
                or manager is None or not isinstance(exact_stdin, bytes)
                or not 1 <= len(exact_stdin) <= 262_144
                or not callable(cancelled) or cancelled()
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 600):
            raise AuthorityDenied("resource.task_start", "root task start binding is unavailable or malformed")
        if (task.node_id != admission.node_id
                or task.admission_id != admission.child_admission_id
                or task.job_id != admission.job_id or task.backend_enrollment_id != admission.backend_enrollment_id
                or task.resource_generation != admission.resource_generation
                or task.process_enrollment_id != admission.process_enrollment_id
                or task.process_generation != admission.process_generation
                or task.native_package_id != admission.native_package_id
                or task.native_package_generation != admission.native_package_generation
                or task.operation_id != admission.operation_id
                or task.task_body_recipe_id != admission.task_body_recipe_id
                or task.task_request_schema_id != admission.task_request_schema_id
                or task.task_payload_sha256 != admission.task_payload_sha256
                or task.parent_closure_digest != admission.parent_closure_digest
                or task.source_context_handle != source.source_context_handle
                or task.parent_closure_digest != source.parent_closure_digest
                or hashlib.sha256(exact_stdin).hexdigest() != task.stdin_sha256
                or len(exact_stdin) != task.stdin_size_bytes
                or source.expires_monotonic <= self.monotonic()
                or admission.expires_monotonic <= self.monotonic()
                or task.deadline_monotonic <= self.monotonic()
                or controller.expires_monotonic <= self.monotonic()
                or controller.service_generation_digest != self.service_generation_digest
                or controller.controller_handle != source.controller_binding_handle
                or controller.subject_profile_id != source.profile_id
                or controller.subject_principal_id != source.principal_id
                or controller.subject_namespace_id != source.namespace_id):
            raise AuthorityDenied("resource.task_start", "admitted task, source or controller binding changed")

        resolve_parent = getattr(jobs, "resolve_admitted_task_parent_context", None)
        if not callable(resolve_parent):
            raise AuthorityDenied("resource.task_start", "root source context resolver is unavailable")
        parent = resolve_parent(admission, admission.node_id, task.source_context_handle)
        if not isinstance(parent, HostContext):
            raise AuthorityDenied("resource.task_start", "root source context is invalid")
        parent_binding = self._binding(parent.uid)
        self._verify_context_signature(parent)
        self._assert_current_context(parent, parent_binding, parent.uid)
        if (parent.profile_id != source.profile_id or parent.principal_id != source.principal_id
                or parent.namespace_id != source.namespace_id
                or parent.native_process_identity is None
                or parent.sensitivity != source.sensitivity
                or parent.generation != self.profile_generations.get(parent.profile_id)):
            raise AuthorityDenied("resource.task_start", "original source context no longer matches its root lineage")

        receipts = tuple(SourceReceipt.from_wire(json.loads(raw.decode("ascii")))
                         for raw in source.signed_receipt_wires)
        if (not receipts or {item.receipt_id for item in receipts}
                != {item.receipt_id for item in parent.source_receipts}
                or len(source.verified_source_receipt_handles) != len(receipts)):
            raise AuthorityDenied("resource.task_start", "complete signed source receipt closure is unavailable")
        for receipt in receipts:
            self._verify_source_receipt(receipt, parent_binding)
        expected_identity = self._native_process_identity(controller.pid, controller.uid)
        live_resolver = getattr(manager, "resolve_live_peer", None)
        if not callable(live_resolver) or controller.controller_profile_id is None:
            raise AuthorityDenied("resource.task_start", "root controller process resolver is unavailable")
        live_identity = live_resolver(
            controller.pid, controller.pidfd, profile_id=controller.controller_profile_id,
            generation=controller.controller_generation,
        )
        if (live_identity is None or live_identity != controller.identity
                or controller.uid != parent.uid
                or expected_identity != parent.native_process_identity
                or any(item.native_process_identity != expected_identity for item in receipts)):
            raise AuthorityDenied("resource.task_start", "source controller PIDFD identity is stale or mismatched")

        resolve_operation = self.selected_operation_resolver
        if not callable(resolve_operation):
            raise AuthorityDenied("resource.task_start", "protected process.start selector is unavailable")
        try:
            selected = resolve_operation(
                admission.process_enrollment_id, admission.process_generation,
                "process.start", selection.operation_id,
            )
        except Exception:
            raise AuthorityDenied("resource.task_start", "selected process operation is unavailable") from None
        profile = getattr(manager, "profiles", {}).get(admission.profile_id)
        child_bindings = [binding for binding in self.bindings_by_uid.values()
                          if binding.profile_id == selection.profile_id]
        child_binding = child_bindings[0] if len(child_bindings) == 1 else None
        if (selected is None or profile is None or child_binding is None
                or selection.profile_id != admission.profile_id
                or selection.profile_generation != admission.profile_generation
                or selection.process_enrollment_id != admission.process_enrollment_id
                or selection.process_generation != admission.process_generation
                or selection.process_start_target != admission.child_target_id
                or selection.principal_id != child_binding.principal_id
                or getattr(selected, "target", None) != selection.process_start_target
                or getattr(selected, "profile_id", None) != profile.profile_id
                or getattr(selected, "principal_id", None) != child_binding.principal_id
                or getattr(selected, "service_uid", None) != child_binding.uid
                or getattr(selected, "enrollment_id", None) != profile.enrollment_id
                or getattr(selected, "generation", None) != profile.generation
                or profile.profile_id != selection.profile_id
                or profile.generation != selection.profile_generation
                or profile.enrollment_id != selection.process_enrollment_id
                or profile.owner_uid != child_binding.uid
                or profile.owner_gid != getattr(selected, "service_gid", None)
                or profile.generation != self.profile_generations.get(profile.profile_id)
                or profile.operation_targets is None
                or profile.operation_targets.get("process.start") != selection.process_start_target
                or admission.child_capability != "hermes-profile-invoke"
                or "hermes-profile-invoke" not in child_binding.capabilities):
            raise AuthorityDenied("resource.task_start", "selected process recipe or root profile binding is stale")

        selection_payload = canonical_bytes({
            "schema": 1, "enrollment_id": profile.enrollment_id,
            "generation": profile.generation,
            "operation_id": selection.operation_id, "parameters": {},
            "admission_handle": admission.handle_id,
            "node_id": task.node_id,
            "task_payload_sha256": task.task_payload_sha256,
            "stdin_sha256": task.stdin_sha256,
            "stdin_size_bytes": task.stdin_size_bytes,
        })
        request_digest = canonical_digest(selection_payload)
        verify_admission = getattr(jobs, "is_admitted_task_current", None)
        if (selection.operation_id != admission.operation_id
                or selection.operation_id != task.operation_id
                or selection.task_body_recipe_id != task.task_body_recipe_id
                or selection.task_request_schema_id != task.task_request_schema_id
                or hashlib.sha256(task.task_payload_bytes).hexdigest() != task.task_payload_sha256
                or not callable(verify_admission)
                or not verify_admission(task, selection_payload)):
            raise AuthorityDenied("resource.task_start", "task recipe selection does not match its admission")
        now = self.monotonic()
        expiry = min(float(admission.expires_monotonic), float(task.deadline_monotonic),
                     float(source.expires_monotonic), now + min(float(timeout), MAX_CONTEXT_LEASE))
        if expiry <= now or cancelled():
            raise AuthorityDenied("resource.task_start", "task start lease expired or was cancelled")
        order = (Sensitivity.PUBLIC, Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN)
        sensitivity = max((parent.sensitivity, *(item.sensitivity for item in receipts)), key=order.index)
        if sensitivity is Sensitivity.PUBLIC:
            raise AuthorityDenied("resource.task_start", "resource task lineage cannot be public")
        lineage_hash = canonical_digest({
            "parent_context": _context_digest(parent),
            "parent_closure_digest": source.parent_closure_digest,
            "receipt_claims": sorted(canonical_digest(item.claims()) for item in receipts),
            "controller_identity": expected_identity,
            "task_payload_sha256": task.task_payload_sha256,
            "stdin_sha256": task.stdin_sha256,
            "selection_digest": request_digest,
        })
        enrollment_id = canonical_digest({
            "uid": child_binding.uid, "principal_id": child_binding.principal_id,
            "profile_id": child_binding.profile_id, "namespace_id": child_binding.namespace_id,
            "generation": profile.generation, "authority_epoch": self.authority_epoch,
        })
        context = HostContext(
            principal_id=child_binding.principal_id, profile_id=child_binding.profile_id,
            namespace_id=child_binding.namespace_id, uid=child_binding.uid,
            purpose="resource-profile-task", intent_id=canonical_digest({
                "job_id": admission.job_id, "node_id": admission.node_id,
                "attempt": admission.attempt_index, "task_sha256": task.task_payload_sha256,
                "selection_digest": request_digest,
            }), trace_id=parent.trace_id, sensitivity=sensitivity,
            lineage_hash=lineage_hash, policy_revision=self._policy_revision(),
            capabilities=child_binding.capabilities, issued_at_monotonic=now,
            monotonic_expires_at=expiry, nonce=secrets.token_urlsafe(24),
            grant_id=secrets.token_urlsafe(24), signature="pending",
            source_receipts=(), final_payload_digest=request_digest,
            enrollment_id=enrollment_id, generation=profile.generation,
            operation="process.start", native_process_identity=expected_identity,
        )
        context = replace(context, signature=self._sign(context.claims()))
        auth_wire = self._authorize_effect(child_binding.uid, {
            "context": context.to_wire(), "capability": "hermes-profile-invoke",
            "target": selection.process_start_target, "recipient": None,
            "request_digest": request_digest, "retry_index": 0,
        })
        authorization = EffectAuthorization.from_wire(auth_wire)
        self._verify_grant_signature(authorization)
        self._assert_grant_current(authorization, child_binding, child_binding.uid)
        self._assert_current_context(context, child_binding, child_binding.uid)
        effect_rule = self.rules.get(("hermes-profile-invoke", "process.start", selection.process_start_target))
        if (effect_rule is None or cancelled() or not self.policy.allow_effect(
                context=context, rule=effect_rule,
                request_digest=request_digest, retry_index=0)):
            raise AuthorityDenied("resource.task_start", "fresh root process.start authorization is no longer active")
        if not verify_admission(task, selection_payload):
            raise AuthorityDenied("resource.task_start", "root task admission expired before launch")
        self._consume(authorization)
        start = getattr(manager, "start_selected_task", None)
        if not callable(start):
            raise AuthorityDenied("resource.task_start", "managed process task start is unavailable")
        result = start(
            profile, context, authorization, selection_payload,
            task_admission=task, admission_handle=admission,
            node_id=task.node_id, admitted_source=source,
            exact_stdin=exact_stdin,
            expected_stdin_sha256=task.stdin_sha256,
            peer_pid=controller.pid, peer_pidfd=controller.pidfd,
            timeout=min(float(timeout), max(0.001, expiry - now)), cancelled=cancelled,
        )
        if not isinstance(result, ManagedTaskHandle) or cancelled():
            raise AuthorityDenied("resource.task_start", "managed process task did not start cleanly")
        return result

    def consume_resource_task_completion(self, receipt: Any, *,
                                         cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        """Consume the runner's one-use terminal/result capsule in-process only."""
        from .resource_jobs import RootResourceProcessReceipt

        runner = self.resource_task_runner
        if runner is None or not isinstance(receipt, RootResourceProcessReceipt) or not callable(cancelled):
            raise AuthorityDenied("resource.task_result", "root task result capsule is unavailable")
        result = runner.consume_resource_task_completion(receipt, cancelled=cancelled)
        if (not isinstance(result, Mapping)
                or set(result) != {"status", "body", "headers", "receipt_id", "result_fields"}
                or type(result["status"]) is not int or not 200 <= result["status"] < 300
                or not isinstance(result["body"], bytes) or len(result["body"]) > MAX_RESPONSE
                or not isinstance(result["headers"], Mapping) or len(result["headers"]) > 16
                or not isinstance(result["receipt_id"], str) or not result["receipt_id"]
                or not isinstance(result["result_fields"], Mapping)
                or cancelled()):
            raise AuthorityDenied("resource.task_result", "root task result capsule is malformed or cancelled")
        return result

    def perform_memory_connector_step(self, reservation_handle: str,
                                     canonical_connector_payload_bytes: bytes,
                                     serialized_service_request_sha256: str, *,
                                     timeout: float,
                                     cancelled: Callable[[], bool]) -> tuple[int, bytes]:
        """Root-private fixed memory step call; never exposed as a worker RPC.

        The attached typed authority must consume the durable one-use step
        reservation, re-resolve the enrolled route and current consent, then
        issue and consume a fresh connector HI12 grant before any service I/O.
        """
        authority = self.memory_step_effect_authority
        if authority is None or not callable(getattr(authority, "perform_memory_connector_step", None)):
            raise AuthorityDenied("memory.step", "root memory step effect authority is unavailable")
        if (not isinstance(reservation_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", reservation_handle)
                or not isinstance(canonical_connector_payload_bytes, bytes)
                or not 1 <= len(canonical_connector_payload_bytes) <= 4 * 1024 * 1024
                or not isinstance(serialized_service_request_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", serialized_service_request_sha256)
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= MAX_CONTEXT_LEASE
                or not callable(cancelled) or cancelled()):
            raise AuthorityDenied("memory.step", "root memory step request is malformed, expired, or cancelled")
        result = authority.perform_memory_connector_step(
            reservation_handle, canonical_connector_payload_bytes,
            serialized_service_request_sha256, timeout=float(timeout), cancelled=cancelled,
        )
        if (not isinstance(result, tuple) or len(result) != 2
                or type(result[0]) is not int or not 100 <= result[0] <= 599
                or not isinstance(result[1], bytes) or len(result[1]) > 4 * 1024 * 1024
                or cancelled()):
            raise AuthorityDenied("memory.step", "root memory connector returned an invalid or cancelled result")
        return result

    def perform_delegated_effect(self, parent_authorization: EffectAuthorization, *,
                                 delegation_id: str, payload: bytes, peer_pid: int,
                                 timeout: float, cancelled: Callable[[], bool]) -> BrokeredEffectResponse:
        """Root-handler-only child effect with fresh child identity and one-use grant.

        This is deliberately not an RPC operation. Only an installed trusted
        effect handler can call it after validating its selected resource/action.
        """
        rule = self.delegations.get(delegation_id)
        if rule is None or not isinstance(parent_authorization, EffectAuthorization):
            raise AuthorityDenied("delegation.unavailable", "fixed delegation is not enrolled")
        parent_binding = self._binding(parent_authorization.uid)
        self._verify_grant_signature(parent_authorization)
        self._assert_grant_current(parent_authorization, parent_binding, parent_authorization.uid)
        parent_effect_rule = self.rules.get((parent_authorization.capability,
                                             parent_authorization.operation,
                                             parent_authorization.target))
        with self._lock:
            consumed = parent_authorization.nonce in self._nonces
            already_delegated = parent_authorization.grant_id in self._delegated_parents
            if consumed and not already_delegated and len(self._delegated_parents) < 100_000:
                self._delegated_parents.add(parent_authorization.grant_id)
        if (not consumed or already_delegated
                or len(self._delegated_parents) >= 100_000
                or parent_binding.profile_id != rule.parent_profile_id
                or parent_authorization.capability != rule.parent_capability
                or parent_effect_rule is None
                or parent_effect_rule.operation != rule.parent_operation
                or parent_effect_rule.target != rule.parent_target
                or parent_effect_rule.recipient != parent_authorization.recipient
                or not self.policy.allow_effect(
                    context=self._context_from_grant(parent_authorization, parent_binding),
                    rule=parent_effect_rule, request_digest=parent_authorization.request_digest,
                    retry_index=parent_authorization.retry_index)):
            raise AuthorityDenied("delegation.denied", "parent effect cannot delegate this child action")
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_REQUEST:
            raise AuthorityDenied("delegation.payload", "child effect payload is outside bounds")
        # All parent claims and child identity come from verified signed records;
        # no caller may select a child principal, UID, namespace or capability.
        child_binding = next((item for item in self.bindings_by_uid.values()
                              if item.profile_id == rule.child_profile_id), None)
        child_effect_rule = self.rules.get((rule.child_capability, rule.child_operation,
                                            rule.child_target))
        if (child_binding is None or rule.child_capability not in child_binding.capabilities
                or child_effect_rule is None or child_effect_rule.operation != rule.child_operation
                or child_effect_rule.recipient != rule.child_recipient
                or (child_effect_rule.operation, child_effect_rule.target) not in self.handlers):
            raise AuthorityDenied("delegation.target", "delegated child target is not enrolled")
        try:
            decoded = json.loads(payload.decode("utf-8"))
            if json.dumps(decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8") != payload:
                raise ValueError
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            raise AuthorityDenied("delegation.payload", "child effect payload must be canonical JSON") from None
        now = self.monotonic()
        expiry = min(parent_authorization.monotonic_expires_at, now + 30.0)
        if expiry <= now or timeout <= 0:
            raise AuthorityDenied("delegation.expired", "parent effect lease has expired")
        payload_digest = canonical_digest(payload)
        context = HostContext(
            principal_id=child_binding.principal_id, profile_id=child_binding.profile_id,
            namespace_id=child_binding.namespace_id, uid=child_binding.uid,
            purpose=rule.child_purpose,
            intent_id=canonical_digest({"delegation": delegation_id,
                                        "parent_intent": parent_authorization.intent_id,
                                        "payload_digest": payload_digest}),
            trace_id=parent_authorization.trace_id,
            sensitivity=parent_authorization.sensitivity,
            lineage_hash=canonical_digest({"parent_lineage": parent_authorization.lineage_hash,
                                           "parent_grant": parent_authorization.grant_id,
                                           "delegation": delegation_id,
                                           "payload_digest": payload_digest}),
            policy_revision=self._policy_revision(), capabilities=child_binding.capabilities,
            issued_at_monotonic=now, monotonic_expires_at=expiry,
            nonce=secrets.token_urlsafe(24), grant_id=secrets.token_urlsafe(24), signature="pending",
            # The parent effect already consumed its source receipts. Preserve
            # their authenticated ancestry and sensitivity through the signed
            # derived lineage hash above, but do not replay the consumed receipt
            # IDs under the child UID.
            source_receipts=(),
            final_payload_digest=payload_digest,
            enrollment_id=canonical_digest({"uid": child_binding.uid,
                                            "principal_id": child_binding.principal_id,
                                            "profile_id": child_binding.profile_id,
                                            "namespace_id": child_binding.namespace_id,
                                            "generation": self.profile_generations.get(child_binding.profile_id, "unversioned"),
                                            "authority_epoch": self.authority_epoch}),
            generation=self.profile_generations.get(child_binding.profile_id, "unversioned"),
            operation=rule.child_operation,
            native_process_identity=parent_authorization.native_process_identity)
        child_context = HostContext.from_wire(self._signed_context(context, self._sign(context.claims())))
        grant_wire = self._authorize_effect(child_binding.uid, {
            "context": child_context.to_wire(), "capability": rule.child_capability,
            "target": rule.child_target, "recipient": rule.child_recipient,
            "request_digest": payload_digest, "retry_index": 0,
        })
        grant = EffectAuthorization.from_wire(grant_wire)
        bounded_timeout = self._bounded(timeout, 30.0)
        effective_timeout = min(bounded_timeout, expiry - self.monotonic())
        if effective_timeout <= 0:
            raise AuthorityDenied("delegation.expired", "child effect lease expired before dispatch")
        response = self._perform_effect(child_binding.uid, peer_pid, {
            "authorization": grant.to_wire(), "operation": rule.child_operation,
            "payload": __import__("base64").b64encode(payload).decode("ascii"),
            "timeout": effective_timeout,
        }, cancelled=lambda: cancelled() or self.monotonic() >= expiry,
            # This call is internal to the root service after the parent grant,
            # selected child profile, and delegated operation have all been
            # verified. The actual kernel peer is the parent process; treating
            # it as the child's SO_PEERCRED identity would reject every
            # intentional cross-UID delegation.
            enforce_peer_identity=False)
        import base64
        return BrokeredEffectResponse(response["status"], base64.b64decode(response["body"], validate=True),
                                      response["headers"], response["receipt_id"])

    def issue_source_receipt(self, parent_context: HostContext, *, source_kind: str,
                             origin_id: str, payload: bytes,
                             ttl_seconds: int = 300) -> SourceReceipt:
        """Mint private provenance only from a trusted in-process source adapter.

        This is deliberately absent from the worker RPC verb set. A registered
        root adapter calls it only after capturing the exact source bytes. No
        caller-provided sensitivity or public declassification is accepted.
        """
        if (not isinstance(parent_context, HostContext) or not isinstance(payload, bytes)
                or not 1 <= len(payload) <= MAX_REQUEST or type(ttl_seconds) is not int
                or not 1 <= ttl_seconds <= 600
                or not parent_context.native_process_identity):
            raise AuthorityDenied("source.request", "trusted source receipt request is malformed")
        if source_kind not in {"native-input", "tool-result", "memory-record", "static-context",
                               "schedule-event", "webhook-event", "provider-result"}:
            raise AuthorityDenied("source.kind", "source kind is not enrolled in the host adapter")
        if not isinstance(origin_id, str) or not 1 <= len(origin_id) <= 256:
            raise AuthorityDenied("source.origin", "source origin is invalid")
        binding = self._binding(parent_context.uid)
        self._verify_context_signature(parent_context)
        self._assert_current_context(parent_context, binding, parent_context.uid)
        now = self.monotonic()
        expiry = min(parent_context.monotonic_expires_at, now + ttl_seconds)
        if expiry <= now:
            raise AuthorityDenied("source.expired", "source context expired before receipt issuance")
        receipt = SourceReceipt(
            receipt_id=secrets.token_urlsafe(24), issuer_id="host-authority",
            source_kind=source_kind, principal_id=binding.principal_id,
            profile_id=binding.profile_id, namespace_id=binding.namespace_id, uid=binding.uid,
            origin_id=origin_id, process_generation=self.profile_generations.get(binding.profile_id, "unversioned"),
            payload_digest=canonical_digest(payload),
            sensitivity=max((Sensitivity.PRIVATE, parent_context.sensitivity),
                            key=lambda value: list(Sensitivity).index(value)),
            parent_lineage_hash=parent_context.lineage_hash,
            policy_revision=self._policy_revision(), recipient_ceiling=frozenset(),
            issued_at_monotonic=now, monotonic_expires_at=expiry, signature="pending",
            enrollment_id=parent_context.enrollment_id or canonical_digest({
                "uid": binding.uid, "principal_id": binding.principal_id,
                "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
                "generation": self.profile_generations.get(binding.profile_id, "unversioned"),
                "authority_epoch": self.authority_epoch,
            }),
            native_process_identity=parent_context.native_process_identity,
            parent_receipt_ids=tuple(sorted(item.receipt_id for item in parent_context.source_receipts)),
            nonce=secrets.token_urlsafe(24),
        )
        return replace(receipt, signature=self._sign(receipt.claims()))

    def issue_observed_source(self, observation: Any) -> Any:
        """Sign and retain one receipt from the root-only observer registry.

        This accepts the proof DTO produced after an enrolled source observer
        captured bytes and revalidated the producer PIDFD, package role, and
        parent closure. It is deliberately not exposed as an RPC operation.
        """
        from .source_observers import (
            MAX_PARENT_RECEIPTS, MAX_OBSERVED_SOURCE_BYTES,
            SourceReceiptHandle, VerifiedSourceObservation,
        )
        if not isinstance(observation, VerifiedSourceObservation):
            raise AuthorityDenied("source.observation", "only a root observer proof can issue source evidence")
        registry = self.source_observer_registry
        consume_proof = getattr(registry, "consume_observation_proof", None)
        if not callable(consume_proof) or consume_proof(observation) is not True:
            raise AuthorityDenied("source.observation", "proof is not issued by the active root source registry")
        context = observation.parent_context
        now = self.monotonic()
        if (observation.authority_epoch != self.authority_epoch
                or not isinstance(observation.event_record_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", observation.event_record_id)
                or not isinstance(observation.origin_id, str)
                or not 1 <= len(observation.origin_id) <= 256
                or type(observation.producer_pid) is not int or observation.producer_pid <= 0
                or type(observation.producer_pidfd) is not int or observation.producer_pidfd < 0
                or not math.isfinite(observation.issued_monotonic)
                or not math.isfinite(observation.expires_monotonic)
                or observation.issued_monotonic > now
                or observation.expires_monotonic <= now
                or observation.expires_monotonic - observation.issued_monotonic > 600
                or len(observation.payload_bytes) > MAX_OBSERVED_SOURCE_BYTES
                or len(observation.parent_receipts) > MAX_PARENT_RECEIPTS
                or context.monotonic_expires_at <= now
                or observation.producer_uid != context.uid
                or observation.profile_id != context.profile_id
                or observation.principal_id != context.principal_id
                or observation.namespace_id != context.namespace_id
                or observation.enrollment_id != context.enrollment_id
                or observation.generation != context.generation):
            raise AuthorityDenied("source.observation", "root observation is stale or mismatched")
        rule = self.rules.get((observation.capability, observation.operation, observation.target_id))
        if (rule is None or rule.operation != observation.operation
                or rule.recipient != observation.recipient):
            raise AuthorityDenied("source.observation", "source action is not an enrolled fixed authority route")
        manager = self.process_effect_handler
        resolve_live_peer = getattr(manager, "resolve_live_peer", None)
        if not callable(resolve_live_peer):
            raise AuthorityDenied("source.observation", "live process custody is unavailable")
        try:
            current_identity = resolve_live_peer(
                observation.producer_pid, observation.producer_pidfd,
                profile_id=observation.profile_id, generation=observation.generation,
            )
        except Exception:
            current_identity = None
        if (current_identity is None or current_identity != observation.producer_identity
                or context.native_process_identity != self._native_process_identity(
                    observation.producer_pid, observation.producer_uid)):
            raise AuthorityDenied("source.peer", "root observer producer identity is no longer current")
        proof = observation.loaded_package_proof
        if (self.service_generation_digest is None or proof is None
                or getattr(proof, "service_generation_digest", None) != self.service_generation_digest
                or getattr(proof, "target_peer_identity", None) != observation.target_peer_identity
                or hashlib.sha256(observation.payload_bytes).hexdigest() != observation.payload_sha256):
            raise AuthorityDenied("source.observation", "loaded source proof is not bound to the active generation")
        try:
            current_target_identity = resolve_live_peer(
                observation.target_peer_pid, observation.target_peer_pidfd,
                profile_id=observation.target_peer_profile_id,
                generation=observation.target_peer_generation,
            )
        except Exception:
            current_target_identity = None
        if (current_target_identity is None
                or current_target_identity != observation.target_peer_identity
                or current_target_identity.kernel_uid != observation.target_peer_uid):
            raise AuthorityDenied("source.target_peer", "root observer target peer identity is no longer current")
        binding = self._binding(context.uid)
        self._verify_context_signature(context)
        self._assert_current_context(context, binding, context.uid)
        parent_ids: set[str] = set()
        for receipt in observation.parent_receipts:
            self._verify_source_receipt(receipt, binding)
            if receipt.profile_id != observation.profile_id:
                raise AuthorityDenied("source.lineage", "parent source receipt is from another profile")
            if receipt.process_generation != observation.generation:
                raise AuthorityDenied("source.lineage", "parent source receipt is from another generation")
            parent_ids.add(receipt.receipt_id)
        if len(parent_ids) != len(observation.parent_receipts):
            raise AuthorityDenied("source.lineage", "root observer parent closure contains duplicates")
        if (len(set(observation.parent_receipt_handles)) != len(observation.parent_receipt_handles)
                or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", item)
                       for item in observation.parent_receipt_handles)):
            raise AuthorityDenied("source.lineage", "root observer parent handles are malformed")
        with self._lock:
            now = self.monotonic()
            self._source_receipt_handles = {
                key: value for key, value in self._source_receipt_handles.items()
                if value.monotonic_expires_at > now
            }
            supplied_parent_ids = set()
            for handle in observation.parent_receipt_handles:
                parent = self._source_receipt_handles.get(handle)
                if parent is None:
                    raise AuthorityDenied("source.lineage", "root observer parent receipt handle is unavailable")
                supplied_parent_ids.add(parent.receipt_id)
            by_parent_id = {item.receipt_id: item for item in self._source_receipt_handles.values()}
            closure_ids = set(supplied_parent_ids)
            pending_ids = list(supplied_parent_ids)
            while pending_ids:
                parent_id = pending_ids.pop()
                parent = by_parent_id.get(parent_id)
                if parent is None:
                    raise AuthorityDenied("source.lineage", "root observer parent closure is incomplete")
                for ancestor_id in parent.parent_receipt_ids:
                    if ancestor_id not in closure_ids:
                        closure_ids.add(ancestor_id)
                        pending_ids.append(ancestor_id)
            if closure_ids != parent_ids:
                raise AuthorityDenied("source.lineage", "root observer parent handles do not match the verified closure")
            if observation.event_record_id in self._observed_event_ids:
                raise AuthorityDenied("source.replay", "root observer event was already issued")
            if len(self._observed_event_ids) >= 100_000 or len(self._source_receipt_handles) >= 100_000:
                raise AuthorityDenied("source.capacity", "root source receipt table is at capacity")
            self._observed_event_ids.add(observation.event_record_id)
        ttl = min(600, int(observation.expires_monotonic - now))
        if ttl < 1:
            raise AuthorityDenied("source.expired", "root observation lease is too short")
        receipt = self.issue_source_receipt(
            context, source_kind=observation.source_kind,
            # VerifiedSourceObservation.origin_id is already derived by the
            # registry from its protected origin and event_record_id. Appending
            # the event here a second time breaks the registry's receipt join.
            origin_id=observation.origin_id,
            payload=observation.payload_bytes, ttl_seconds=ttl,
        )
        receipt = replace(
            receipt, parent_receipt_ids=tuple(sorted(parent_ids)), signature="pending",
        )
        receipt = replace(receipt, signature=self._sign(receipt.claims()))
        handle = SourceReceiptHandle(secrets.token_urlsafe(32))
        with self._lock:
            if handle in self._source_receipt_handles:
                raise AuthorityDenied("source.capacity", "opaque source receipt handle collision")
            self._source_receipt_handles[str(handle)] = receipt
        return handle

    def revalidate_effect(self, context: HostContext, authorization: EffectAuthorization, *,
                          operation: str, request_digest: str,
                          retry_index: int) -> bool:
        """Fresh non-consuming check for a handler's final pre-effect boundary."""
        if (not isinstance(context, HostContext)
                or not isinstance(authorization, EffectAuthorization)
                or not isinstance(operation, str)
                or not isinstance(request_digest, str)
                or not isinstance(retry_index, int) or isinstance(retry_index, bool)):
            raise AuthorityDenied("effect.revalidation", "effect revalidation binding is malformed")
        binding = self._binding(context.uid)
        self._verify_grant_signature(authorization)
        self._assert_grant_current(authorization, binding, context.uid)
        expected = self._context_from_grant(authorization, binding)
        if any(getattr(context, field) != getattr(expected, field) for field in (
                "principal_id", "profile_id", "namespace_id", "uid", "purpose", "intent_id",
                "trace_id", "sensitivity", "lineage_hash", "policy_revision", "capabilities",
                "monotonic_expires_at", "source_receipts", "final_payload_digest", "enrollment_id",
                "generation", "operation", "native_process_identity")):
            raise AuthorityDenied("effect.revalidation", "handler context differs from the signed grant")
        rule = self.rules.get((authorization.capability, operation, authorization.target))
        if (rule is None or rule.operation != operation
                or authorization.operation != operation
                or authorization.source_receipts != context.source_receipts
                or authorization.request_digest != request_digest
                or authorization.retry_index != retry_index
                or any(rule.recipient is not None and rule.recipient not in receipt.recipient_ceiling
                       for receipt in context.source_receipts)
                or not self.policy.allow_effect(context=context, rule=rule,
                                                request_digest=request_digest,
                                                retry_index=retry_index)):
            raise AuthorityDenied("effect.revalidation", "fresh host policy denied the final effect boundary")
        return True

    def serve_unix(self, socket_path: Path, *, socket_gid: int,
                   stop_event: threading.Event,
                   expected_uid: int = 0, max_clients: int = 32) -> None:
        """Serve bounded one-RPC connections on a protected fixed Unix socket.

        The method refuses to unlink or replace any existing path. Packaging
        owns creation of the root-controlled parent directory and service unit.
        """
        if (not socket_path.is_absolute() or type(socket_gid) is not int or socket_gid < 0
                or type(expected_uid) is not int or expected_uid < 0
                or type(max_clients) is not int or not 1 <= max_clients <= 128):
            raise ValueError("invalid authority listener configuration")
        parent = socket_path.parent.lstat()
        if (stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != expected_uid or parent.st_mode & 0o022):
            raise AuthorityDenied("authority.socket", "authority socket directory custody is invalid")
        try:
            socket_path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise AuthorityDenied("authority.socket", "authority socket path already exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        pool = ThreadPoolExecutor(max_workers=max_clients, thread_name_prefix="authority-rpc")
        slots = threading.BoundedSemaphore(max_clients)
        try:
            listener.bind(str(socket_path))
            os.chown(socket_path, expected_uid, socket_gid)
            os.chmod(socket_path, 0o660)
            listener.listen(max_clients)
            listener.settimeout(0.25)
            while not stop_event.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                if not slots.acquire(blocking=False):
                    connection.close()
                    continue
                def serve_one(conn: socket.socket = connection) -> None:
                    try:
                        self.handle_connection(conn)
                    finally:
                        conn.close()
                        slots.release()
                try:
                    pool.submit(serve_one)
                except RuntimeError:
                    connection.close()
                    slots.release()
                    raise
        finally:
            listener.close()
            pool.shutdown(wait=True, cancel_futures=True)
            try:
                info = socket_path.lstat()
                if stat.S_ISSOCK(info.st_mode) and info.st_uid == expected_uid:
                    socket_path.unlink()
            except OSError:
                pass

    @classmethod
    def from_key_file(cls, path: Path, *, key_id: str,
                      expected_uid: int = 0, **kwargs: Any) -> "AuthorityService":
        parent = path.parent.lstat()
        if (stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != expected_uid or parent.st_mode & 0o022):
            raise AuthorityDenied("key.custody", "authority signing key directory custody is invalid")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o077:
                    raise AuthorityDenied("key.custody", "authority signing key custody is invalid")
                data = os.read(fd, 33)
            finally:
                os.close(fd)
        except OSError:
            raise AuthorityDenied("key.custody", "authority signing key is unavailable") from None
        if len(data) != 32:
            raise AuthorityDenied("key.custody", "authority signing key has invalid length")
        return cls(signing_key=data, key_id=key_id, **kwargs)

    def handle_connection(self, connection: socket.socket) -> None:
        """Authenticate kernel peer, issue challenge, and process exactly one RPC."""
        peer_pidfd: int | None = None
        try:
            connection.settimeout(MAX_CONTEXT_LEASE + 25.0)
            peer_pid, uid = self._peer_credentials(connection)
            if not hasattr(os, "pidfd_open"):
                raise AuthorityDenied("peer.pidfd", "kernel parent-death handle is unavailable")
            try:
                # Pin the SO_PEERCRED process identity before parsing attacker-
                # controlled RPC bytes or scheduling any handler work.
                peer_pidfd = os.pidfd_open(peer_pid, 0)
            except OSError:
                raise AuthorityDenied("peer.pidfd", "kernel peer exited before authority dispatch") from None
            hello = self._read_json_line(connection, MAX_REQUEST)
            if hello != {"version": 1, "operation": "hello"}:
                raise AuthorityDenied("protocol.handshake", "invalid authority handshake")
            nonce = secrets.token_urlsafe(32)
            self._write_json_line(connection, {"version": 1, "server_nonce": nonce}, MAX_RESPONSE)
            request = self._read_json_line(connection, MAX_REQUEST)
            if not isinstance(request, dict) or set(request) != {"version", "operation", "server_nonce", "client_nonce", "payload"}:
                raise AuthorityDenied("protocol.request", "authority request fields are invalid")
            if request["version"] != 1 or request["server_nonce"] != nonce:
                raise AuthorityDenied("protocol.replay", "authority handshake nonce mismatch")
            client_nonce = request["client_nonce"]
            if not isinstance(client_nonce, str) or not 32 <= len(client_nonce) <= 128:
                raise AuthorityDenied("protocol.request", "authority client nonce is invalid")
            with self._lock:
                now = self.monotonic()
                self._client_nonces = {key: expiry for key, expiry in self._client_nonces.items() if expiry > now}
                if client_nonce in self._client_nonces:
                    raise AuthorityDenied("protocol.replay", "authority request nonce was replayed")
                if len(self._client_nonces) >= 100_000:
                    raise AuthorityDenied("protocol.capacity", "authority replay protection is at capacity")
                self._client_nonces[client_nonce] = now + 130.0
            result = self._dispatch(uid, peer_pid, peer_pidfd, request["operation"], request["payload"],
                                   cancelled=lambda: self._peer_disconnected(connection))
            response = {"version": 1, "server_nonce": nonce, "result": result, "error": None}
        except AuthorityDenied as exc:
            response = {"version": 1, "server_nonce": locals().get("nonce", ""), "result": None,
                        "error": {"code": exc.code, "message": str(exc)}}
        except Exception:
            response = {"version": 1, "server_nonce": locals().get("nonce", ""), "result": None,
                        "error": {"code": "authority.failure", "message": "host authority request failed"}}
        try:
            self._write_json_line(connection, response, MAX_RESPONSE)
        except (OSError, AuthorityDenied):
            pass
        finally:
            if peer_pidfd is not None:
                os.close(peer_pidfd)

    def _dispatch(self, uid: int, peer_pid: int, peer_pidfd: int | None,
                  operation: Any, payload: Any,
                  *, cancelled: Callable[[], bool]) -> Any:
        if operation == "issue_context":
            if isinstance(payload, dict) and "source_receipts" in payload:
                raise AuthorityDenied("source.handle", "workers must resolve opaque source receipt handles")
            return self._issue_context(uid, payload, peer_pid=peer_pid)
        if operation == "authorize_effect":
            return self._authorize_effect(uid, payload, peer_pid=peer_pid)
        if operation == "authorize_process_start":
            return self._authorize_process_start(uid, peer_pid, payload)
        if operation == "verify_effect":
            return self._verify_effect(uid, payload, peer_pid=peer_pid)
        if operation == "perform_effect":
            return self._perform_effect(uid, peer_pid, payload, cancelled=cancelled,
                                        peer_pidfd=peer_pidfd)
        if operation == "process.control":
            return self._dispatch_process_control(
                uid, peer_pid, peer_pidfd, payload, cancelled=cancelled,
            )
        if operation == "prepare_native_event":
            broker = self.native_bridge_broker
            if broker is None or peer_pidfd is None:
                raise AuthorityDenied("native.unavailable", "native source producer is not enrolled")
            return broker.prepare(uid=uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                                  payload=payload, cancelled=cancelled)
        if operation == "dispatch_native_request":
            broker = self.native_bridge_broker
            if broker is None or peer_pidfd is None:
                raise AuthorityDenied("native.unavailable", "native provider gateway is not enrolled")
            return broker.dispatch(uid=uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                                   payload=payload, cancelled=cancelled)
        if operation in {"native.invocation.begin", "native.invocation.contexts"}:
            return self._dispatch_native_invocation(
                operation, uid, peer_pid, peer_pidfd, payload,
            )
        if operation == "native.input.take":
            return self._dispatch_native_input_take(
                uid, peer_pid, peer_pidfd, payload, cancelled=cancelled,
            )
        if operation == "native.turn.finish":
            return self._dispatch_native_turn_finish(
                uid, peer_pid, peer_pidfd, payload, cancelled=cancelled,
            )
        if operation == "native.response.take":
            registry = self.native_invocation_registry
            if registry is None or peer_pidfd is None:
                raise AuthorityDenied("native.response.take", "root provider response registry is unavailable")
            expected = {"schema", "delivery_handle", "response_body_sha256", "native_request_handle"}
            if (not isinstance(payload, dict) or set(payload) != expected
                    or type(payload.get("schema")) is not int or payload["schema"] != 1
                    or not isinstance(payload.get("delivery_handle"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{43}", payload["delivery_handle"])
                    or not isinstance(payload.get("response_body_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", payload["response_body_sha256"])
                    or not isinstance(payload.get("native_request_handle"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", payload["native_request_handle"])):
                raise AuthorityDenied("native.response.take", "provider response lookup request is malformed")
            take = getattr(registry, "take_native_response_metadata", None)
            if not callable(take):
                raise AuthorityDenied("native.response.take", "root provider response lookup is unavailable")
            metadata = take(
                uid, peer_pid, peer_pidfd, payload["delivery_handle"],
                payload["response_body_sha256"], payload["native_request_handle"],
            )
            result = metadata.to_wire() if callable(getattr(metadata, "to_wire", None)) else metadata
            if (not isinstance(result, Mapping)
                    and isinstance(getattr(result, "producer_context_handle", None), str)
                    and isinstance(getattr(result, "tool_call_bindings", None), tuple)):
                result = {
                    "producer_context_handle": result.producer_context_handle,
                    "tool_call_bindings": list(result.tool_call_bindings),
                }
            fields = {"producer_context_handle", "tool_call_bindings", "turn_handle",
                      "final_response_delivery_handle"}
            if (not isinstance(result, Mapping) or set(result) != fields
                    or not isinstance(result["producer_context_handle"], str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", result["producer_context_handle"])
                    or not isinstance(result["tool_call_bindings"], (list, tuple))
                    or len(result["tool_call_bindings"]) > 128
                    or result["turn_handle"] is not None
                       and (not isinstance(result["turn_handle"], str)
                            or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", result["turn_handle"]))
                    or result["final_response_delivery_handle"] is not None
                       and (not isinstance(result["final_response_delivery_handle"], str)
                            or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}",
                                                result["final_response_delivery_handle"]))):
                raise AuthorityDenied("native.response.take", "root provider response metadata is invalid")
            from .types import NativeToolCallBinding
            calls = tuple(item if isinstance(item, NativeToolCallBinding)
                          else NativeToolCallBinding.from_wire(item)
                          for item in result["tool_call_bindings"])
            if len({item.observed_call_handle for item in calls}) != len(calls):
                raise AuthorityDenied("native.response.take", "root provider call handles are duplicated")
            return {"producer_context_handle": result["producer_context_handle"],
                    "tool_call_bindings": [item.to_wire() if callable(getattr(item, "to_wire", None))
                                           else {"observed_call_handle": item.observed_call_handle,
                                                 "provider_tool_call_id": item.provider_tool_call_id,
                                                 "tool_name": item.tool_name,
                                                 "arguments_sha256": item.arguments_sha256}
                                           for item in calls],
                    "turn_handle": result["turn_handle"],
                    "final_response_delivery_handle": result["final_response_delivery_handle"]}
        if operation == "native.mcp.dispatch":
            return self._dispatch_native_mcp(uid, peer_pid, peer_pidfd, payload, cancelled=cancelled)
        if operation == "source.receipt.take":
            delivery = self.source_receipt_delivery
            if delivery is None or peer_pidfd is None:
                raise AuthorityDenied("source.delivery", "peer-bound source receipt delivery is unavailable")
            if (not isinstance(payload, dict) or set(payload) != {"schema", "receipt_handle"}
                    or payload.get("schema") != 1
                    or not isinstance(payload.get("receipt_handle"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", payload["receipt_handle"])):
                raise AuthorityDenied("source.delivery", "source receipt take request is malformed")
            take = getattr(delivery, "take_source_receipt", None)
            if not callable(take):
                raise AuthorityDenied("source.delivery", "peer-bound source delivery adapter is unavailable")
            result = take(payload["receipt_handle"], peer_uid=uid, peer_pid=peer_pid,
                          peer_pidfd=peer_pidfd)
            if str(result) != payload["receipt_handle"]:
                raise AuthorityDenied("source.delivery", "source receipt delivery adapter returned another handle")
            return {"schema": 1, "receipt_handle": str(result)}
        if operation in {
            "admit_remote_session", "challenge_remote_session", "renew_remote_session",
            "close_remote_session", "open_remote_connector", "read_remote_connector",
            "write_remote_connector", "close_remote_connector",
        }:
            return self._dispatch_remote_session(
                operation, uid, peer_pid, peer_pidfd, payload,
            )
        raise AuthorityDenied("protocol.operation", "authority operation is unavailable")

    def _dispatch_native_invocation(self, operation: str, peer_uid: int,
                                    peer_pid: int, peer_pidfd: int | None,
                                    payload: Any) -> Mapping[str, Any]:
        """Resolve only root-observed invocation records for this live peer."""
        registry = self.native_invocation_registry
        if registry is None or peer_pidfd is None:
            raise AuthorityDenied("native.invocation", "root observed invocation registry is unavailable")
        if operation == "native.invocation.begin":
            expected = {"schema", "producer_context_handle", "observed_call_handle",
                        "canonical_arguments_b64"}
            if (not isinstance(payload, dict) or set(payload) != expected
                    or type(payload.get("schema")) is not int or payload["schema"] != 1
                    or any(not isinstance(payload.get(key), str)
                           or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", payload[key])
                           for key in ("producer_context_handle", "observed_call_handle"))
                    or not isinstance(payload.get("canonical_arguments_b64"), str)
                    or len(payload["canonical_arguments_b64"]) > 2_800_000):
                raise AuthorityDenied("native.invocation", "native invocation begin request is malformed")
            try:
                arguments = base64.b64decode(payload["canonical_arguments_b64"], validate=True)
            except (ValueError, TypeError):
                raise AuthorityDenied("native.invocation", "native invocation arguments are malformed") from None
            if (not 1 <= len(arguments) <= 2 * 1024 * 1024
                    or base64.b64encode(arguments).decode("ascii") != payload["canonical_arguments_b64"]):
                raise AuthorityDenied("native.invocation", "native invocation arguments exceed their bound")
            binding = registry.begin_native_invocation(
                peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                producer_context_handle=payload["producer_context_handle"],
                observed_call_handle=payload["observed_call_handle"],
                canonical_arguments=arguments,
            )
            result = binding.to_wire() if callable(getattr(binding, "to_wire", None)) else binding
            fields = {"schema", "invocation_handle", "package_id", "profile_id", "generation",
                      "adapter_id", "action_id", "arguments_sha256", "parent_closure_digest",
                      "expires_monotonic", "binding_sha256"}
            if not isinstance(result, Mapping) or set(result) != fields:
                raise AuthorityDenied("native.invocation", "root invocation registry returned an invalid binding")
            return dict(result)
        expected = {"schema", "invocation_handle"}
        if (not isinstance(payload, dict) or set(payload) != expected
                or type(payload.get("schema")) is not int or payload["schema"] != 1
                or not isinstance(payload.get("invocation_handle"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", payload["invocation_handle"])):
            raise AuthorityDenied("native.invocation", "native invocation context request is malformed")
        contexts = registry.get_invocation_contexts(
            peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            invocation_handle=payload["invocation_handle"],
        )
        result = contexts.to_wire() if callable(getattr(contexts, "to_wire", None)) else contexts
        fields = {"schema", "invocation_handle", "source_receipt_handles",
                  "parent_closure_digest", "arguments_sha256", "expires_monotonic"}
        if (not isinstance(result, Mapping) or set(result) != fields
                or result.get("invocation_handle") != payload["invocation_handle"]
                or not isinstance(result.get("source_receipt_handles"), (list, tuple))
                or len(result["source_receipt_handles"]) > 128):
            raise AuthorityDenied("native.invocation", "root invocation registry returned invalid ancestry")
        return {**dict(result), "source_receipt_handles": list(result["source_receipt_handles"])}

    def _dispatch_native_mcp(self, peer_uid: int, peer_pid: int,
                             peer_pidfd: int | None, payload: Any,
                             *, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        """Dispatch one lexical native MCP call through the root-selected handler."""
        import base64

        dispatcher = self.native_mcp_dispatcher
        if dispatcher is None or peer_pidfd is None:
            raise AuthorityDenied("native.mcp", "root native MCP dispatcher is unavailable")
        fields = {"schema", "invocation_handle", "canonical_arguments_b64"}
        if (not isinstance(payload, dict) or set(payload) != fields
                or type(payload.get("schema")) is not int or payload["schema"] != 1
                or not isinstance(payload.get("invocation_handle"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", payload["invocation_handle"])
                or not isinstance(payload.get("canonical_arguments_b64"), str)
                or len(payload["canonical_arguments_b64"]) > 2_800_000):
            raise AuthorityDenied("native.mcp", "native MCP request fields are malformed")
        try:
            arguments = base64.b64decode(payload["canonical_arguments_b64"], validate=True)
        except (ValueError, TypeError):
            raise AuthorityDenied("native.mcp", "native MCP arguments are malformed") from None
        if (not 1 <= len(arguments) <= 2 * 1024 * 1024
                or base64.b64encode(arguments).decode("ascii") != payload["canonical_arguments_b64"]):
            raise AuthorityDenied("native.mcp", "native MCP arguments exceed their bound")
        try:
            value = strict_json_loads(arguments.decode("utf-8"))
            if not isinstance(value, dict) or canonical_bytes(value) != arguments:
                raise ValueError
        except (ValueError, TypeError, UnicodeError):
            raise AuthorityDenied("native.mcp", "native MCP arguments are not canonical JSON") from None
        if cancelled():
            raise AuthorityDenied("native.mcp", "native MCP request was cancelled")
        try:
            response = dispatcher.dispatch_native_mcp(
                peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                invocation_handle=payload["invocation_handle"],
                canonical_arguments=arguments, cancelled=cancelled,
            )
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("native.mcp", "root native MCP dispatch failed") from None
        if isinstance(response, BrokeredEffectResponse):
            status, body, headers, receipt_id = (
                response.status, response.body, response.headers, response.receipt_id,
            )
            source_handle = response.source_receipt_handle
            if response.producer_context_handle is not None or response.tool_call_bindings:
                raise AuthorityDenied("native.mcp", "native MCP response contains unrelated provider metadata")
        elif isinstance(response, Mapping):
            allowed = {"status", "body", "headers", "receipt_id"}
            if set(response) not in (allowed, allowed | {"source_receipt_handle"}):
                raise AuthorityDenied("native.mcp", "root native MCP response fields are malformed")
            status, body, headers, receipt_id = (response["status"], response["body"],
                                                 response["headers"], response["receipt_id"])
            source_handle = response.get("source_receipt_handle")
        else:
            raise AuthorityDenied("native.mcp", "root native MCP response type is invalid")
        if (type(status) is not int or not 0 <= status <= 599
                or not isinstance(body, bytes) or len(body) > 4 * 1024 * 1024
                or not isinstance(headers, Mapping) or len(headers) > 32
                or any(not isinstance(key, str) or not isinstance(item, str)
                       or any(char in key + item for char in "\r\n\x00")
                       for key, item in headers.items())
                or not isinstance(receipt_id, str) or not 1 <= len(receipt_id) <= 256
                or source_handle is not None and (not isinstance(source_handle, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", source_handle))):
            raise AuthorityDenied("native.mcp", "root native MCP response exceeds its bound")
        return {"status": status, "body": base64.b64encode(body).decode("ascii"),
                "headers": dict(headers), "receipt_id": receipt_id,
                **({"source_receipt_handle": source_handle} if source_handle is not None else {})}

    def _dispatch_native_input_take(self, peer_uid: int, peer_pid: int,
                                   peer_pidfd: int | None, payload: Any, *,
                                   cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        """Take only the queued input selected for this live authenticated peer."""
        from .source_observers import NativeInitialInputDelivery

        registry = self.native_input_delivery_registry
        if (registry is None or peer_pidfd is None
                or not isinstance(payload, dict) or set(payload) != {"schema"}
                or type(payload.get("schema")) is not int or payload["schema"] != 1):
            raise AuthorityDenied("native.input.take", "selected native input delivery is unavailable")
        if cancelled():
            raise AuthorityDenied("native.input.take", "selected native input request was cancelled")
        try:
            delivery = registry.take_selected_native_input(
                peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            )
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("native.input.take", "selected native input lookup failed") from None
        if delivery is None:
            return {"schema": 1, "state": "pending"}
        if type(delivery) is not NativeInitialInputDelivery:
            raise AuthorityDenied("native.input.take", "root input registry returned an invalid delivery")
        result = delivery.to_wire()
        expected = {"schema", "source_receipt_handle", "selected_execution_handle",
                    "input_sha256", "input_size_bytes", "expires_monotonic"}
        if (not isinstance(result, Mapping) or set(result) not in (expected, expected | {"turn_handle"})
                or type(result.get("schema")) is not int or result["schema"] != 1
                or not isinstance(result.get("source_receipt_handle"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", result["source_receipt_handle"])
                or not isinstance(result.get("selected_execution_handle"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", result["selected_execution_handle"])
                or not isinstance(result.get("input_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", result["input_sha256"])
                or type(result.get("input_size_bytes")) is not int
                or not 1 <= result["input_size_bytes"] <= 1_048_576
                or isinstance(result.get("expires_monotonic"), bool)
                or type(result.get("expires_monotonic")) not in (int, float)
                or not self.monotonic() < result["expires_monotonic"] <= self.monotonic() + 30.0
                or result.get("turn_handle") is not None and (
                    not isinstance(result.get("turn_handle"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", result["turn_handle"]))):
            raise AuthorityDenied("native.input.take", "root input delivery fields exceed their bounds")
        return dict(result)

    def _dispatch_process_control(self, uid: int, peer_pid: int,
                                  peer_pidfd: int | None, payload: Any, *,
                                  cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        """Resolve an active process handle and authorize its fixed control verb.

        The caller supplies only an opaque handle, generation, operation, and
        bounded operation fields. The root process manager selects the profile
        and target from its live handle registry; target/capability/grant are
        never accepted from the worker.
        """
        if (peer_pidfd is None or not isinstance(payload, dict)
                or set(payload) != {"schema", "operation", "process_id", "generation", "fields"}
                or payload.get("schema") != 1):
            raise AuthorityDenied("process.control", "process control request is malformed")
        operation = payload.get("operation")
        process_id, generation, fields = (payload.get("process_id"), payload.get("generation"),
                                           payload.get("fields"))
        if (operation not in {"process.status", "process.read", "process.write", "process.stop", "process.inspect"}
                or not isinstance(process_id, str)
                or not re.fullmatch(r"[0-9a-f]{32}", process_id)
                or not isinstance(generation, str)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", generation)
                or not isinstance(fields, dict)):
            raise AuthorityDenied("process.control", "process control selection is invalid")
        expected = {
            "process.status": set(), "process.inspect": set(),
            "process.stop": {"reason", "grace_seconds"},
            "process.read": {"stream", "maximum_bytes"},
            "process.write": {"data_bytes", "sequence"},
        }[operation]
        if set(fields) != expected:
            raise AuthorityDenied("process.control", "process control fields do not match the fixed verb")
        if operation == "process.read":
            if (fields.get("stream") not in {"stdout", "stderr"}
                    or type(fields.get("maximum_bytes")) is not int
                    or not 1 <= fields["maximum_bytes"] <= 1_048_576):
                raise AuthorityDenied("process.control", "process read bounds are invalid")
        if operation == "process.write":
            data = fields.get("data_bytes")
            if (not isinstance(data, str) or len(data) > 349_528
                    or type(fields.get("sequence")) is not int
                    or fields["sequence"] < 0):
                raise AuthorityDenied("process.control", "process write bounds are invalid")
            try:
                decoded = base64.b64decode(data, validate=True)
            except Exception:
                raise AuthorityDenied("process.control", "process write data is malformed") from None
            if len(decoded) > 262_144 or base64.b64encode(decoded).decode("ascii") != data:
                raise AuthorityDenied("process.control", "process write data exceeds its bound")
        if operation == "process.stop":
            if (fields.get("reason") not in {"cancel", "shutdown", "rollback"}
                    or type(fields.get("grace_seconds")) is not int
                    or not 0 <= fields["grace_seconds"] <= 10):
                raise AuthorityDenied("process.control", "process stop bounds are invalid")

        manager = self.process_effect_handler
        resolver = getattr(manager, "resolve_process_operation", None)
        if not callable(resolver):
            raise AuthorityDenied("process.control", "root process handle resolver is unavailable")
        try:
            selected = resolver(process_id, generation, operation, peer_uid=uid,
                                peer_pid=peer_pid, peer_pidfd=peer_pidfd)
        except Exception:
            selected = None
        if (not isinstance(selected, tuple) or len(selected) != 2
                or not isinstance(selected[1], str)):
            raise AuthorityDenied("process.handle", "process handle is stale or not owned by this peer")
        profile, target = selected
        binding = self._binding(uid)
        if (getattr(profile, "profile_id", None) != binding.profile_id
                or getattr(profile, "generation", None) != generation
                or self.profile_generations.get(binding.profile_id) != generation):
            raise AuthorityDenied("process.binding", "process handle profile or generation changed")
        enrolled_target = getattr(profile, "operation_targets", {}).get(operation)
        if enrolled_target is None:
            from hermes_installer.managed_process_custodian import (
                process_control_target, process_inspect_target,
            )
            enrolled_target = (process_inspect_target(profile) if operation == "process.inspect"
                               else process_control_target(profile, operation))
        if target != enrolled_target:
            raise AuthorityDenied("process.target", "process manager returned a non-enrolled control target")
        rule = self.rules.get(("hermes-process-control", operation, target))
        if rule is None or rule.recipient is not None:
            raise AuthorityDenied("process.target", "process control effect is not enrolled")

        request_body = {"schema": 1, "operation": operation,
                        "process_id": process_id, "generation": generation,
                        "fields": fields}
        request_bytes = canonical_bytes(request_body)
        request_digest = canonical_digest(request_bytes)
        context_wire = self._issue_context(uid, {
            "purpose": "managed-process-control",
            "intent": f"{operation}:{process_id}:{generation}:{request_digest}",
            "trace_id": secrets.token_urlsafe(24),
            "lease_seconds": 5.0,
            "source_contexts": [], "final_payload_digest": request_digest,
            "operation": operation,
        }, peer_pid=peer_pid)
        grant_wire = self._authorize_effect(uid, {
            "context": context_wire, "capability": rule.capability,
            "target": target, "recipient": rule.recipient,
            "request_digest": request_digest, "retry_index": 0,
        }, peer_pid=peer_pid)
        return self._perform_effect(uid, peer_pid, {
            "authorization": grant_wire, "operation": operation,
            "payload": base64.b64encode(request_bytes).decode("ascii"),
            "timeout": 5.0,
        }, cancelled=cancelled, peer_pidfd=peer_pidfd)

    def _dispatch_remote_session(self, operation: str, peer_uid: int, peer_pid: int,
                                 peer_pidfd: int | None, payload: Any) -> Mapping[str, Any]:
        """Dispatch typed HI13 operations using only socket-derived peer identity."""
        authority = self.remote_session_authority
        if authority is None or peer_pidfd is None:
            raise AuthorityDenied("remote.unavailable", "root remote session authority is not enrolled")
        if not isinstance(payload, dict):
            raise AuthorityDenied("remote.request", "remote authority request is malformed")
        import base64

        def text_field(name: str) -> str:
            value = payload.get(name)
            if not isinstance(value, str) or not value:
                raise AuthorityDenied("remote.request", "remote authority request is malformed")
            return value

        def token_field(name: str, maximum: int) -> bytes:
            value = text_field(name)
            try:
                decoded = base64.b64decode(value, validate=True)
            except Exception:
                raise AuthorityDenied("remote.request", "remote authority byte field is malformed") from None
            if not 1 <= len(decoded) <= maximum:
                raise AuthorityDenied("remote.request", "remote authority byte field exceeds its bound")
            return decoded

        peer = {"peer_uid": peer_uid, "peer_pid": peer_pid, "peer_pidfd": peer_pidfd}
        if operation == "admit_remote_session":
            if set(payload) != {"access_jwt_b64", "request"}:
                raise AuthorityDenied("remote.request", "remote admission fields are invalid")
            from .remote_sessions import MAX_JWT_BYTES, RemoteAdmissionRequest
            request = RemoteAdmissionRequest.from_wire(payload["request"])
            return authority.admit_remote_session(
                token_field("access_jwt_b64", MAX_JWT_BYTES), request, **peer,
            ).to_wire()
        if operation == "renew_remote_session":
            if set(payload) != {"remote_session_handle", "access_jwt_b64", "renewal_nonce"}:
                raise AuthorityDenied("remote.request", "remote renewal fields are invalid")
            from .remote_sessions import MAX_JWT_BYTES
            return authority.renew_remote_session(
                text_field("remote_session_handle"), token_field("access_jwt_b64", MAX_JWT_BYTES),
                text_field("renewal_nonce"), **peer,
            ).to_wire()
        handle = text_field("remote_session_handle")
        if operation in {"challenge_remote_session", "close_remote_session", "open_remote_connector"}:
            if set(payload) != {"remote_session_handle"}:
                raise AuthorityDenied("remote.request", "remote session fields are invalid")
            method = {
                "challenge_remote_session": authority.challenge_remote_session,
                "close_remote_session": authority.close_remote_session,
                "open_remote_connector": authority.open_remote_connector,
            }[operation]
            return method(handle, **peer).to_wire()
        if operation == "read_remote_connector":
            if set(payload) != {"remote_session_handle", "connector_handle", "sequence", "maximum_bytes"}:
                raise AuthorityDenied("remote.request", "remote read fields are invalid")
            sequence, maximum = payload["sequence"], payload["maximum_bytes"]
            if type(sequence) is not int or type(maximum) is not int:
                raise AuthorityDenied("remote.request", "remote read bounds are invalid")
            return authority.read_remote_connector(
                handle, text_field("connector_handle"), sequence, maximum, **peer,
            ).to_wire()
        if operation == "write_remote_connector":
            if set(payload) != {"remote_session_handle", "connector_handle", "sequence", "data_bytes_b64"}:
                raise AuthorityDenied("remote.request", "remote write fields are invalid")
            sequence = payload["sequence"]
            if type(sequence) is not int:
                raise AuthorityDenied("remote.request", "remote write sequence is invalid")
            from .remote_sessions import MAX_FRAME_BYTES
            data = token_field("data_bytes_b64", MAX_FRAME_BYTES)
            return authority.write_remote_connector(
                handle, text_field("connector_handle"), sequence, data, **peer,
            ).to_wire()
        if operation == "close_remote_connector":
            if set(payload) != {"remote_session_handle", "connector_handle"}:
                raise AuthorityDenied("remote.request", "remote connector close fields are invalid")
            return authority.close_remote_connector(
                handle, text_field("connector_handle"), **peer,
            ).to_wire()
        raise AuthorityDenied("protocol.operation", "remote authority operation is unavailable")

    def _authorize_process_start(self, uid: int, peer_pid: int | None, payload: Any) -> dict[str, Any]:
        """Resolve process.start target from root enrollment, never caller input."""
        required = {"context", "enrollment_id", "generation", "operation_id",
                    "request_digest", "retry_index"}
        if not isinstance(payload, dict) or set(payload) != required:
            raise AuthorityDenied("effect.request", "selected process authorization fields are invalid")
        if (self.selected_operation_resolver is None
                or any(not isinstance(payload.get(field), str) or not payload[field]
                       for field in ("enrollment_id", "generation", "operation_id"))
                or not isinstance(payload["request_digest"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", payload["request_digest"])
                or type(payload["retry_index"]) is not int
                or not 0 <= payload["retry_index"] <= 100):
            raise AuthorityDenied("effect.unavailable", "protected selected process operation is unavailable")
        binding = self._binding(uid)
        context = HostContext.from_wire(payload["context"])
        self._verify_context_signature(context)
        self._assert_current_context(context, binding, uid)
        if (context.operation != "process.start"
                or context.final_payload_digest != payload["request_digest"]):
            raise AuthorityDenied("effect.binding", "selected process context does not bind the exact request")
        try:
            selected = self.selected_operation_resolver(
                payload["enrollment_id"], payload["generation"], "process.start",
                payload["operation_id"])
        except Exception:
            raise AuthorityDenied("effect.target", "selected process enrollment is unavailable") from None
        if (getattr(selected, "operation", None) != "process.start"
                or getattr(selected, "operation_id", None) != payload["operation_id"]
                or getattr(selected, "profile_id", None) != binding.profile_id
                or getattr(selected, "principal_id", None) != binding.principal_id
                or getattr(selected, "service_uid", None) != uid
                or getattr(selected, "enrollment_id", None) != payload["enrollment_id"]
                or getattr(selected, "generation", None) != payload["generation"]
                or not isinstance(getattr(selected, "target", None), str)
                or "hermes-profile-invoke" not in binding.capabilities):
            raise AuthorityDenied("effect.target", "selected process operation is not bound to this host principal")
        return self._authorize_effect(uid, {
            "context": context.to_wire(), "capability": "hermes-profile-invoke",
            "target": selected.target, "recipient": None,
            "request_digest": payload["request_digest"],
            "retry_index": payload["retry_index"],
        }, peer_pid=peer_pid)

    def _binding(self, uid: int) -> PrincipalBinding:
        binding = self.bindings_by_uid.get(uid)
        if binding is None:
            raise AuthorityDenied("principal.unenrolled", "kernel peer UID has no enrolled profile")
        return binding

    def _issue_context(self, uid: int, payload: Any, *, allow_expired_sources: bool = False,
                       peer_pid: int | None = None,
                       inherited_process_identity: str | None = None) -> dict[str, Any]:
        required = {"purpose", "intent", "trace_id", "lease_seconds", "source_contexts"}
        optional = {"source_receipts", "source_receipt_handles", "final_payload_digest", "operation"}
        if (not isinstance(payload, dict) or not required.issubset(payload)
                or set(payload) - required - optional):
            raise AuthorityDenied("context.request", "context request fields are invalid")
        binding = self._binding(uid)
        purpose, intent = payload["purpose"], payload["intent"]
        if (not isinstance(purpose, str) or not 1 <= len(purpose) <= 128
                or not isinstance(intent, str) or not 1 <= len(intent) <= 512):
            raise AuthorityDenied("context.request", "purpose or intent is invalid")
        lease = self._bounded(payload["lease_seconds"], MAX_CONTEXT_LEASE)
        raw_sources = payload["source_contexts"]
        if not isinstance(raw_sources, list) or len(raw_sources) > 64:
            raise AuthorityDenied("context.lineage", "source lineage exceeds its bound")
        sources = tuple(HostContext.from_wire(item) for item in raw_sources)
        raw_receipts = payload.get("source_receipts", [])
        raw_handles = payload.get("source_receipt_handles", [])
        if not isinstance(raw_receipts, list) or len(raw_receipts) > 64:
            raise AuthorityDenied("context.lineage", "source receipts are malformed or mixed with context lineage")
        if (not isinstance(raw_handles, list) or len(raw_handles) > 64
                or raw_receipts and raw_handles):
            raise AuthorityDenied("context.lineage", "source receipt handles are malformed")
        parsed_receipts = [SourceReceipt.from_wire(item) for item in raw_receipts]
        now = self.monotonic()
        for source in sources:
            self._verify_context_signature(source)
            if (source.uid != uid or source.profile_id != binding.profile_id
                    or source.principal_id != binding.principal_id
                    or source.namespace_id != binding.namespace_id
                    or (not allow_expired_sources and source.monotonic_expires_at <= now)
                    or source.policy_revision != self._policy_revision()):
                raise AuthorityDenied("context.lineage", "source context belongs to another principal")
            parsed_receipts.extend(source.source_receipts)
        if raw_handles:
            if peer_pid is None:
                raise AuthorityDenied("source.handle", "source handles require an authenticated native peer")
            current_identity = self._native_process_identity(peer_pid, uid)
            now_for_handles = self.monotonic()
            with self._lock:
                self._source_receipt_handles = {
                    handle: receipt for handle, receipt in self._source_receipt_handles.items()
                    if receipt.monotonic_expires_at > now_for_handles
                }
                resolved: list[SourceReceipt] = []
                for handle in raw_handles:
                    receipt = self._source_receipt_handles.get(handle) if isinstance(handle, str) else None
                    if (receipt is None or receipt.uid != uid
                            or receipt.native_process_identity != current_identity):
                        raise AuthorityDenied("source.handle", "source receipt handle is unknown or bound to another peer")
                    resolved.append(receipt)
            parsed_receipts.extend(resolved)
        if len(parsed_receipts) > 64:
            raise AuthorityDenied("context.lineage", "complete source receipt closure exceeds its bound")
        receipts = tuple({receipt.receipt_id: receipt for receipt in parsed_receipts}.values())
        if len(receipts) != len(parsed_receipts):
            # Repeated references are accepted only if they name identical
            # immutable signed evidence; conflicting copies are rejected.
            for receipt in parsed_receipts:
                if receipt != next(item for item in receipts if item.receipt_id == receipt.receipt_id):
                    raise AuthorityDenied("context.lineage", "source receipt identifier has conflicting claims")
        receipt_ids = {receipt.receipt_id for receipt in receipts}
        if any(not set(receipt.parent_receipt_ids).issubset(receipt_ids) for receipt in receipts):
            raise AuthorityDenied("context.lineage", "source receipt parent closure is incomplete")
        for receipt in receipts:
            self._verify_source_receipt(receipt, binding, allow_expired=allow_expired_sources)
        trace_id = payload["trace_id"] or secrets.token_urlsafe(24)
        if not isinstance(trace_id, str) or not 1 <= len(trace_id) <= 128:
            raise AuthorityDenied("context.request", "trace ID is invalid")
        final_payload_digest = payload.get("final_payload_digest")
        if final_payload_digest is not None and (not isinstance(final_payload_digest, str)
                                                 or len(final_payload_digest) != 64
                                                 or any(char not in "0123456789abcdef" for char in final_payload_digest)):
            raise AuthorityDenied("context.request", "final payload digest is invalid")
        if receipts and final_payload_digest is None:
            raise AuthorityDenied("context.lineage", "source receipts require a final payload digest")
        operation = payload.get("operation")
        if operation not in _OPERATIONS:
            raise AuthorityDenied("context.operation", "context operation is not a fixed host effect")
        generation = self.profile_generations.get(binding.profile_id, "unversioned")
        enrollment_id = canonical_digest({"uid": uid, "principal_id": binding.principal_id,
                                           "profile_id": binding.profile_id,
                                           "namespace_id": binding.namespace_id,
                                           "generation": generation,
                                           "authority_epoch": self.authority_epoch})
        native_process_identity = inherited_process_identity
        if peer_pid is not None:
            native_process_identity = self._native_process_identity(peer_pid, uid)
        if receipts and (not native_process_identity or any(
                receipt.native_process_identity != native_process_identity for receipt in receipts)):
            raise AuthorityDenied("context.lineage", "source receipt is bound to another native process")
        if sources and (not native_process_identity or any(
                source.native_process_identity != native_process_identity for source in sources)):
            raise AuthorityDenied("context.lineage", "source context is bound to another native process")
        sensitivity, lineage_hash = self.policy.classify(
            purpose=purpose, intent=intent, source_contexts=sources, binding=binding)
        if receipts:
            order = (Sensitivity.PUBLIC, Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN)
            # A root-issued receipt may refine an otherwise empty UNKNOWN
            # source set, but can never lower sensitivity or public-clear it.
            receipt_sensitivity = max((item.sensitivity for item in receipts), key=order.index)
            sensitivity = max((sensitivity, receipt_sensitivity), key=order.index)
            lineage_hash = canonical_digest({
                "base": lineage_hash,
                "receipts": sorted((item.receipt_id, canonical_digest(item.claims())) for item in receipts),
                "parents": sorted(item.parent_lineage_hash for item in receipts),
            })
        if not isinstance(sensitivity, Sensitivity):
            raise AuthorityDenied("policy.classification", "host policy returned an invalid classification")
        now = self.monotonic()
        context = HostContext(
            principal_id=binding.principal_id, profile_id=binding.profile_id,
            namespace_id=binding.namespace_id, uid=uid, purpose=purpose,
            intent_id=canonical_digest({"purpose": purpose, "intent": intent}),
            trace_id=trace_id, sensitivity=sensitivity, lineage_hash=lineage_hash,
            policy_revision=self._policy_revision(), capabilities=binding.capabilities,
            issued_at_monotonic=now, monotonic_expires_at=now + lease,
            nonce=secrets.token_urlsafe(24), grant_id=secrets.token_urlsafe(24), signature="pending",
            source_receipts=receipts, final_payload_digest=final_payload_digest,
            enrollment_id=enrollment_id, generation=generation, operation=operation,
            native_process_identity=native_process_identity,
        )
        signature = self._sign(context.claims())
        return HostContext(**{**context.__dict__, "signature": signature}).to_wire() if hasattr(context, "__dict__") else self._signed_context(context, signature)

    def create_background_consent(self, context: HostContext, *, provider_id: str,
                                  owner_generation: int, ttl_seconds: int = 300) -> BackgroundConsent:
        """Issue source-bound consent for fixed automatic memory stages.

        Intended only for the root-owned memory enqueue handler. The user
        facing worker cannot call this method over the authority RPC protocol.
        """
        if not isinstance(context, HostContext):
            raise AuthorityDenied("memory.consent", "a host-issued context is required")
        binding = self._binding(context.uid)
        self._verify_context_signature(context)
        self._assert_current_context(context, binding, context.uid)
        if (not isinstance(provider_id, str) or not provider_id
                or type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 86_400):
            raise AuthorityDenied("memory.consent", "memory consent binding or lifetime is invalid")
        owner_state = self.memory_owner_state
        if (owner_state is None or type(owner_generation) is not int or owner_generation < 1
                or owner_state(context.profile_id) != (provider_id, owner_generation)
                or self.rules.get(("memory-capture", "memory.enqueue",
                                   f"memory:{provider_id}:enqueue")) is None):
            raise AuthorityDenied("memory.consent", "memory provider generation or enqueue target is not enrolled")
        enqueue_rule = self.rules[("memory-capture", "memory.enqueue",
                                   f"memory:{provider_id}:enqueue")]
        if (enqueue_rule.operation, enqueue_rule.target) not in self.handlers:
            raise AuthorityDenied("memory.consent", "root memory enqueue handler is unavailable")
        consent_digest = canonical_digest({"context": _context_digest(context), "provider": provider_id,
                                           "owner_generation": owner_generation})
        if ("memory-capture" not in context.capabilities
                or not self.policy.allow_effect(context=context, rule=enqueue_rule,
                                                request_digest=consent_digest, retry_index=0)):
            raise AuthorityDenied("memory.consent", "fresh memory capture policy denied enqueue")
        now = self.wall_clock()
        claims = {
            "kind": "memory-background-consent-v1", "consent_id": secrets.token_urlsafe(24),
            "source_context_digest": _context_digest(context),
            "principal_id": context.principal_id, "profile_id": context.profile_id,
            "namespace_id": context.namespace_id, "uid": context.uid,
            "provider_id": provider_id, "owner_generation": owner_generation,
            "policy_revision": self._policy_revision(),
            "allowed_actions": ["extract", "embed", "capture"],
            "issued_at_unix": now, "expires_at_unix": now + ttl_seconds,
        }
        return BackgroundConsent(claims, self._sign(claims))

    def context_for_job(self, source_context_wire: bytes | Mapping[str, Any],
                        consent_wire: bytes | Mapping[str, Any], *, provider_id: str,
                        owner_generation: int, action: str, trace_id: str | None = None,
                        lease_seconds: float = 30.0,
                        final_payload_digest: str | None = None) -> HostContext:
        """Reissue a fresh short context from valid persisted source consent."""
        source = self._decode_wire(source_context_wire, "source context")
        consent = self._decode_wire(consent_wire, "background consent")
        if not isinstance(source, dict) or not isinstance(consent, dict):
            raise AuthorityDenied("memory.consent", "source or consent record is malformed")
        signature = consent.pop("signature", None)
        expected = {"kind", "consent_id", "source_context_digest", "principal_id", "profile_id",
                    "namespace_id", "uid", "provider_id", "owner_generation", "policy_revision",
                    "allowed_actions", "issued_at_unix", "expires_at_unix"}
        if set(consent) != expected or not isinstance(signature, str):
            raise AuthorityDenied("memory.consent", "background consent schema is invalid")
        self._verify_signature(consent, signature)
        source_context = HostContext.from_wire(source)
        self._verify_context_signature(source_context)
        now_wall = self.wall_clock()
        if (consent["kind"] != "memory-background-consent-v1"
                or consent["source_context_digest"] != _context_digest(source_context)
                or consent["principal_id"] != source_context.principal_id
                or consent["profile_id"] != source_context.profile_id
                or consent["namespace_id"] != source_context.namespace_id
                or consent["uid"] != source_context.uid
                or consent["provider_id"] != provider_id
                or consent["owner_generation"] != owner_generation
                or consent["policy_revision"] != self._policy_revision()
                or type(consent["owner_generation"]) is not int
                or action not in consent["allowed_actions"]
                or type(consent["issued_at_unix"]) not in (int, float)
                or type(consent["expires_at_unix"]) not in (int, float)
                or consent["expires_at_unix"] <= now_wall
                or consent["issued_at_unix"] > now_wall
                or consent["expires_at_unix"] - consent["issued_at_unix"] > 86_400
                or not self.background_consent_active(consent["consent_id"])):
            raise AuthorityDenied("memory.consent", "background consent is expired, revoked or differently bound")
        binding = self._binding(source_context.uid)
        if (binding.profile_id != source_context.profile_id
                or binding.principal_id != source_context.principal_id
                or binding.namespace_id != source_context.namespace_id
                or self.memory_owner_state is None
                or self.memory_owner_state(binding.profile_id) != (provider_id, owner_generation)):
            raise AuthorityDenied("memory.consent", "background owner identity or generation changed")
        if source_context.policy_revision != self._policy_revision():
            raise AuthorityDenied("memory.consent", "source policy revision is stale")
        intent = f"memory:{provider_id}:{action}:{source_context.lineage_hash}"
        wire = self._issue_context(source_context.uid, {
            "purpose": f"memory-{action}", "intent": intent, "trace_id": trace_id,
            "lease_seconds": lease_seconds, "source_contexts": [source_context.to_wire()],
            "final_payload_digest": final_payload_digest,
            "operation": f"memory.{action}",
        }, allow_expired_sources=True,
           inherited_process_identity=source_context.native_process_identity)
        return HostContext.from_wire(wire)

    def perform_memory_effect(self, source_context_wire: bytes | Mapping[str, Any],
                              consent_wire: bytes | Mapping[str, Any], *, provider_id: str,
                              owner_generation: int, action: str, capability: str,
                              payload: bytes,
                              trace_id: str | None = None, timeout: float = 30.0,
                              cancelled: Callable[[], bool] = lambda: False) -> Any:
        """Run one memory stage with a fresh context, authorization and broker dispatch."""
        capabilities = {"extract": "memory-extraction", "embed": "memory-embedding",
                        "capture": "memory-capture"}
        expected_capability = capabilities.get(action)
        if expected_capability is None or capability != expected_capability or not isinstance(payload, bytes):
            raise AuthorityDenied("memory.effect", "memory stage or canonical payload is invalid")
        context = self.context_for_job(source_context_wire, consent_wire, provider_id=provider_id,
                                       owner_generation=owner_generation, action=action,
                                       trace_id=trace_id, final_payload_digest=canonical_digest(payload))
        target = f"memory:{provider_id}:{action}"
        digest = canonical_digest(payload)
        authorization = self._authorize_effect(context.uid, {
            "context": context.to_wire(), "capability": capability, "target": target,
            "recipient": None, "request_digest": digest, "retry_index": 0,
        })
        consent_value = self._decode_wire(consent_wire, "background consent")
        consent_id = consent_value.get("consent_id") if isinstance(consent_value, dict) else None
        if not isinstance(consent_id, str):
            raise AuthorityDenied("memory.consent", "background consent identifier is missing")
        def effect_cancelled() -> bool:
            owner_current = (self.memory_owner_state is not None
                             and self.memory_owner_state(context.profile_id) == (provider_id, owner_generation))
            return cancelled() or not owner_current or not self.background_consent_active(consent_id)
        result = self._perform_effect(context.uid, os.getpid(), {
            "authorization": authorization, "operation": f"memory.{action}",
            "payload": __import__("base64").b64encode(payload).decode("ascii"),
            "timeout": timeout,
        }, cancelled=effect_cancelled, enforce_peer_identity=False)
        import base64
        return BrokeredEffectResponse(result["status"], base64.b64decode(result["body"], validate=True),
                                      result["headers"], result["receipt_id"])

    @staticmethod
    def _decode_wire(value: bytes | Mapping[str, Any], label: str) -> Any:
        if isinstance(value, Mapping):
            return dict(value)
        if not isinstance(value, bytes) or len(value) > 262_144:
            raise AuthorityDenied("memory.consent", f"{label} exceeds its wire bound")
        try:
            return json.loads(value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AuthorityDenied("memory.consent", f"{label} is malformed") from None

    def _signed_context(self, context: HostContext, signature: str) -> dict[str, Any]:
        fields = context.claims()
        fields["signature"] = signature
        return fields

    def _authorize_effect(self, uid: int, payload: Any, *, peer_pid: int | None = None) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"context", "capability", "target", "recipient", "request_digest", "retry_index"}:
            raise AuthorityDenied("effect.request", "effect request fields are invalid")
        binding = self._binding(uid)
        context = HostContext.from_wire(payload["context"])
        self._verify_context_signature(context)
        self._assert_current_context(context, binding, uid, peer_pid=peer_pid)
        capability, target, recipient = payload["capability"], payload["target"], payload["recipient"]
        request_digest, retry_index = payload["request_digest"], payload["retry_index"]
        if (not isinstance(capability, str) or not isinstance(target, str)
                or recipient is not None and not isinstance(recipient, str)
                or not isinstance(request_digest, str) or len(request_digest) != 64
                or type(retry_index) is not int or not 0 <= retry_index <= 100):
            raise AuthorityDenied("effect.request", "effect binding is invalid")
        rule = self.rules.get((capability, context.operation, target))
        if (rule is None or (rule.operation, rule.target) not in self.handlers
                or rule.recipient != recipient
                or context.operation != rule.operation
                or context.final_payload_digest != request_digest
                or any(recipient is not None and recipient not in receipt.recipient_ceiling
                       for receipt in context.source_receipts)
                or not self.policy.allow_effect(context=context, rule=rule,
                                                request_digest=request_digest, retry_index=retry_index)):
            raise AuthorityDenied("effect.denied", "host policy denied this exact effect")
        if capability not in context.capabilities:
            raise AuthorityDenied("effect.denied", "profile has no enrolled capability for this effect")
        now = self.monotonic()
        effect_lease = _EFFECT_LEASE_BY_OPERATION.get(rule.operation, MAX_EFFECT_LEASE)
        expiry = min(context.monotonic_expires_at, now + effect_lease)
        grant = EffectAuthorization(
            principal_id=context.principal_id, profile_id=context.profile_id,
            namespace_id=context.namespace_id, uid=uid, purpose=context.purpose,
            sensitivity=context.sensitivity, trace_id=context.trace_id,
            policy_revision=context.policy_revision, lineage_hash=context.lineage_hash,
            capability=capability, intent_id=context.intent_id, target=target,
            recipient=recipient, request_digest=request_digest,
            retry_index=retry_index, issued_at_monotonic=now,
            monotonic_expires_at=expiry, grant_id=secrets.token_urlsafe(24),
            nonce=secrets.token_urlsafe(24), context_digest=_context_digest(context),
            signature="pending", source_receipts=context.source_receipts,
            final_payload_digest=context.final_payload_digest,
            enrollment_id=context.enrollment_id, generation=context.generation,
            operation=rule.operation, native_process_identity=context.native_process_identity,
        )
        signed = self._sign(grant.claims())
        return {**grant.claims(), "signature": signed}

    def _verify_effect(self, uid: int, payload: Any, *, peer_pid: int | None = None) -> dict[str, Any]:
        grant, context, rule = self._parse_effect_request(uid, payload, peer_pid=peer_pid)
        return {"operation": rule.operation, "verified_at_monotonic": self.monotonic(),
                "verification_receipt": secrets.token_urlsafe(24)}

    def _perform_effect(self, uid: int, peer_pid: int, payload: Any,
                        *, cancelled: Callable[[], bool],
                        peer_pidfd: int | None = None,
                        enforce_peer_identity: bool = True,
                        source_receipt_ids_to_consume: frozenset[str] | None = None) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"authorization", "operation", "payload", "timeout"}:
            raise AuthorityDenied("effect.request", "broker request fields are invalid")
        import base64
        try:
            body = base64.b64decode(payload["payload"], validate=True)
        except Exception:
            raise AuthorityDenied("effect.request", "broker payload is malformed") from None
        timeout = self._bounded(payload["timeout"], MAX_CONTEXT_LEASE)
        grant = EffectAuthorization.from_wire(payload["authorization"])
        binding = self._binding(uid)
        self._verify_grant_signature(grant)
        self._assert_grant_current(grant, binding, uid)
        if canonical_digest(body) != grant.request_digest:
            raise AuthorityDenied("effect.binding", "broker payload digest mismatch")
        rule = self.rules.get((grant.capability, grant.operation, grant.target))
        if (rule is None or rule.operation != payload["operation"]
                or rule.recipient != grant.recipient
                or grant.operation != payload["operation"]
                or grant.final_payload_digest != grant.request_digest):
            raise AuthorityDenied("effect.binding", "fixed effect operation does not match protected target")
        context = self._context_from_grant(grant, binding)
        if (enforce_peer_identity
                and context.native_process_identity != self._native_process_identity(peer_pid, uid)):
            raise AuthorityDenied("peer.process", "effect grant belongs to a different native process")
        if not self.policy.allow_effect(context=context, rule=rule,
                                        request_digest=grant.request_digest,
                                        retry_index=grant.retry_index):
            raise AuthorityDenied("effect.denied", "fresh host policy denied the fixed effect")
        handler = self.handlers.get((rule.operation, rule.target))
        if handler is None:
            raise AuthorityDenied("effect.unavailable", "fixed effect handler is not installed")
        self._consume(grant, source_receipt_ids_to_consume=source_receipt_ids_to_consume)
        started = self.monotonic()
        remaining = min(timeout, grant.monotonic_expires_at - started)
        if remaining <= 0:
            raise AuthorityDenied("effect.expired", "fixed effect grant expired before dispatch")
        cancellation = lambda: (self.monotonic() >= grant.monotonic_expires_at or cancelled())
        def current_or_cancelled() -> bool:
            if cancellation():
                return True
            try:
                self.revalidate_effect(context, grant, operation=rule.operation,
                                       request_digest=grant.request_digest,
                                       retry_index=grant.retry_index)
                return False
            except AuthorityDenied:
                return True
        response = handler(context=context, authorization=grant,
                           payload=body, timeout=remaining,
                           peer_pid=peer_pid,
                           peer_pidfd=peer_pidfd,
                           cancelled=current_or_cancelled)
        if current_or_cancelled():
            raise AuthorityDenied("effect.expired", "fixed effect exceeded its grant lease")
        if not isinstance(response, Mapping) or set(response) != {"status", "body", "headers", "receipt_id"}:
            raise AuthorityDenied("effect.response", "fixed effect handler returned an invalid response")
        body_bytes = response["body"]
        if not isinstance(body_bytes, bytes) or len(body_bytes) > 4 * 1024 * 1024:
            raise AuthorityDenied("effect.response", "fixed effect response exceeds its bound")
        headers = response["headers"]
        receipt_id = response["receipt_id"]
        if type(response["status"]) is not int or not 0 <= response["status"] <= 599:
            raise AuthorityDenied("effect.response", "fixed effect status is invalid")
        if (not isinstance(headers, Mapping) or len(headers) > 32
                or any(not isinstance(key, str) or not isinstance(value, str)
                       or not key or len(key) > 128 or len(value) > 2048
                       or any(char in key + value for char in "\r\n\x00")
                       for key, value in headers.items())
                or not isinstance(receipt_id, str) or not 1 <= len(receipt_id) <= 256):
            raise AuthorityDenied("effect.response", "fixed effect response headers or receipt are invalid")
        result: dict[str, Any] = {
            "status": response["status"], "body": base64.b64encode(body_bytes).decode("ascii"),
            "headers": dict(headers), "receipt_id": receipt_id,
        }
        observer = self.native_runtime_observer
        observer_key = (rule.capability, rule.operation, rule.target)
        observer_ids = getattr(observer, "effect_observer_ids", {}) if observer is not None else {}
        if (observer is not None and observer_key in observer_ids
                and 200 <= response["status"] < 300):
            observe = getattr(observer, "observe_effect_result", None)
            if not callable(observe):
                raise AuthorityDenied("source.observer", "root native result observer is unavailable")
            handle = observe(
                service=self, context=context, authorization=grant,
                operation=rule.operation, target=rule.target,
                response_status=response["status"], result_payload=body_bytes,
                peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                cancelled=current_or_cancelled,
            )
            if not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle):
                raise AuthorityDenied("source.observer", "root result observer returned an invalid receipt handle")
            delivery = self.source_receipt_delivery
            take = getattr(delivery, "take_source_receipt", None)
            if not callable(take) or peer_pidfd is None:
                raise AuthorityDenied("source.delivery", "peer-bound result receipt delivery is unavailable")
            delivered = take(handle, peer_uid=uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
            if str(delivered) != handle:
                raise AuthorityDenied("source.delivery", "root delivered a different result receipt handle")
            # The registry atomically marks this handle delivered to the exact
            # live peer before the opaque reference enters the response.
            result["source_receipt_handle"] = handle
        return result

    def _dispatch_native_turn_finish(self, peer_uid: int, peer_pid: int,
                                     peer_pidfd: int | None, payload: Any, *,
                                     cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        """Return only the opaque presentation from the authenticated turn registry."""
        from .types import RootCompletedNativeTurnPresentation

        registry = self.native_turn_observation_registry
        fields = {"schema", "turn_handle", "final_response_delivery_handle"}
        if (registry is None or peer_pidfd is None
                or not isinstance(payload, dict) or set(payload) != fields
                or type(payload.get("schema")) is not int or payload["schema"] != 1
                or not isinstance(payload.get("turn_handle"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", payload["turn_handle"])
                or not isinstance(payload.get("final_response_delivery_handle"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", payload["final_response_delivery_handle"])):
            raise AuthorityDenied("native.turn.finish", "native turn finish request is malformed or unavailable")
        if cancelled():
            raise AuthorityDenied("native.turn.finish", "native turn finish request was cancelled")
        try:
            presentation = registry.finish_selected_native_turn(
                peer_uid, peer_pid, peer_pidfd, payload["turn_handle"],
                payload["final_response_delivery_handle"],
            )
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("native.turn.finish", "root native turn verification failed") from None
        if (type(presentation) is not RootCompletedNativeTurnPresentation
                or presentation.turn_handle != payload["turn_handle"]
                or presentation.state != "completed"
                or presentation.expires_monotonic <= self.monotonic()):
            raise AuthorityDenied("native.turn.finish", "root native turn presentation is invalid or expired")
        return presentation.to_wire()

    def _parse_effect_request(self, uid: int, payload: Any, *, peer_pid: int | None = None
                              ) -> tuple[EffectAuthorization, HostContext, EffectRule]:
        if not isinstance(payload, dict) or set(payload) != {"authorization", "context", "capability", "target", "recipient", "request_digest", "retry_index"}:
            raise AuthorityDenied("effect.request", "effect verification fields are invalid")
        grant = EffectAuthorization.from_wire(payload["authorization"])
        context = HostContext.from_wire(payload["context"])
        binding = self._binding(uid)
        self._verify_context_signature(context)
        self._verify_grant_signature(grant)
        self._assert_current_context(context, binding, uid, peer_pid=peer_pid)
        self._assert_grant_current(grant, binding, uid)
        if (grant.context_digest != _context_digest(context)
                or grant.source_receipts != context.source_receipts
                or grant.final_payload_digest != context.final_payload_digest
                or grant.operation != context.operation
                or context.final_payload_digest != grant.request_digest
                or grant.capability != payload["capability"] or grant.target != payload["target"]
                or grant.recipient != payload["recipient"] or grant.request_digest != payload["request_digest"]
                or grant.retry_index != payload["retry_index"]):
            raise AuthorityDenied("effect.binding", "effect grant binding mismatch")
        rule = self.rules.get((grant.capability, grant.operation, grant.target))
        if rule is None or rule.recipient != grant.recipient:
            raise AuthorityDenied("effect.denied", "fixed effect target is not enrolled")
        if not self.policy.allow_effect(context=context, rule=rule,
                                        request_digest=grant.request_digest,
                                        retry_index=grant.retry_index):
            raise AuthorityDenied("effect.denied", "fresh host policy denied the fixed effect")
        return grant, context, rule

    def _assert_current_context(self, context: HostContext, binding: PrincipalBinding, uid: int, *,
                                peer_pid: int | None = None) -> None:
        expected_generation = self.profile_generations.get(binding.profile_id, "unversioned")
        expected_enrollment = canonical_digest({
            "uid": binding.uid, "principal_id": binding.principal_id,
            "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
            "generation": expected_generation, "authority_epoch": self.authority_epoch,
        })
        if (context.uid != uid or context.principal_id != binding.principal_id
                or context.profile_id != binding.profile_id or context.namespace_id != binding.namespace_id
                or context.monotonic_expires_at <= self.monotonic()
                or context.policy_revision != self._policy_revision()
                or context.generation != expected_generation
                or context.enrollment_id != expected_enrollment):
            raise AuthorityDenied("context.stale", "host context is stale or bound to another principal")
        if (peer_pid is not None
                and context.native_process_identity != self._native_process_identity(peer_pid, uid)):
            raise AuthorityDenied("context.process", "host context is bound to another native process")
        for receipt in context.source_receipts:
            self._verify_source_receipt(receipt, binding)

    def _assert_grant_current(self, grant: EffectAuthorization, binding: PrincipalBinding, uid: int) -> None:
        expected_generation = self.profile_generations.get(binding.profile_id, "unversioned")
        expected_enrollment = canonical_digest({
            "uid": binding.uid, "principal_id": binding.principal_id,
            "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
            "generation": expected_generation, "authority_epoch": self.authority_epoch,
        })
        if (grant.uid != uid or grant.principal_id != binding.principal_id
                or grant.profile_id != binding.profile_id or grant.namespace_id != binding.namespace_id
                or grant.monotonic_expires_at <= self.monotonic()
                or grant.policy_revision != self._policy_revision()
                or grant.generation != expected_generation
                or grant.enrollment_id != expected_enrollment):
            raise AuthorityDenied("grant.stale", "effect grant is stale or bound to another principal")
        for receipt in grant.source_receipts:
            self._verify_source_receipt(receipt, binding)

    def _context_from_grant(self, grant: EffectAuthorization, binding: PrincipalBinding) -> HostContext:
        # Handler receives only claims already authenticated by this service.
        return HostContext(
            principal_id=binding.principal_id, profile_id=binding.profile_id,
            namespace_id=binding.namespace_id, uid=binding.uid,
            purpose=grant.purpose, intent_id=grant.intent_id,
            trace_id=grant.trace_id, sensitivity=grant.sensitivity,
            lineage_hash=grant.lineage_hash, policy_revision=grant.policy_revision,
            capabilities=binding.capabilities, issued_at_monotonic=grant.issued_at_monotonic,
            monotonic_expires_at=grant.monotonic_expires_at, nonce=grant.nonce,
            grant_id=grant.grant_id, signature="verified-in-service",
            source_receipts=grant.source_receipts,
            final_payload_digest=grant.final_payload_digest,
            enrollment_id=grant.enrollment_id, generation=grant.generation,
            operation=grant.operation, native_process_identity=grant.native_process_identity,
        )

    def _consume(self, grant: EffectAuthorization, *,
                 source_receipt_ids_to_consume: frozenset[str] | None = None) -> None:
        with self._lock:
            now = self.monotonic()
            self._nonces = {nonce: expiry for nonce, expiry in self._nonces.items() if expiry > now}
            self._source_receipts_consumed = {
                receipt_id: expiry for receipt_id, expiry in self._source_receipts_consumed.items()
                if expiry > now
            }
            if grant.nonce in self._nonces:
                raise AuthorityDenied("grant.replay", "effect grant was already consumed")
            grant_receipt_ids = {receipt.receipt_id for receipt in grant.source_receipts}
            receipt_ids = (grant_receipt_ids if source_receipt_ids_to_consume is None
                           else set(source_receipt_ids_to_consume))
            if not receipt_ids.issubset(grant_receipt_ids):
                raise AuthorityDenied("source.binding", "effect cannot consume unrelated source evidence")
            if receipt_ids & self._source_receipts_consumed.keys():
                raise AuthorityDenied("source.replay", "source receipt was already used by another effect")
            if len(self._nonces) >= 100_000 or len(self._source_receipts_consumed) + len(receipt_ids) > 100_000:
                raise AuthorityDenied("grant.capacity", "effect replay protection is at capacity")
            self._nonces[grant.nonce] = grant.monotonic_expires_at
            for receipt in grant.source_receipts:
                if receipt.receipt_id in receipt_ids:
                    self._source_receipts_consumed[receipt.receipt_id] = receipt.monotonic_expires_at

    def _verify_context_signature(self, context: HostContext) -> None:
        self._verify_signature(context.claims(), context.signature)

    def _verify_source_receipt(self, receipt: SourceReceipt, binding: PrincipalBinding,
                               *, allow_expired: bool = False) -> None:
        self._verify_signature(receipt.claims(), receipt.signature)
        expected_enrollment = canonical_digest({
            "uid": binding.uid, "principal_id": binding.principal_id,
            "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
            "generation": self.profile_generations.get(binding.profile_id, "unversioned"),
            "authority_epoch": self.authority_epoch,
        })
        if (receipt.issuer_id != "host-authority"
                or receipt.uid != binding.uid
                or receipt.principal_id != binding.principal_id
                or receipt.profile_id != binding.profile_id
                or receipt.namespace_id != binding.namespace_id
                or receipt.process_generation != self.profile_generations.get(binding.profile_id, "unversioned")
                or receipt.enrollment_id != expected_enrollment
                or not receipt.native_process_identity
                or receipt.nonce == ""
                or receipt.policy_revision != self._policy_revision()
                or receipt.sensitivity not in {Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN}
                or not allow_expired and receipt.monotonic_expires_at <= self.monotonic()):
            raise AuthorityDenied("source.lineage", "source receipt is stale or bound to another host identity")

    def _verify_grant_signature(self, grant: EffectAuthorization) -> None:
        self._verify_signature(grant.claims(), grant.signature)

    def _verify_signature(self, claims: Mapping[str, Any], signature: str) -> None:
        unsigned = dict(claims)
        unsigned.pop("key_id", None)
        expected = self._sign(unsigned)
        if not hmac.compare_digest(expected, signature):
            raise AuthorityDenied("signature.invalid", "host authority signature is invalid")

    def _sign(self, claims: Mapping[str, Any]) -> str:
        envelope = {"key_id": self.key_id, **claims}
        data = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return hmac.new(self._key, data, hashlib.sha256).hexdigest()

    def _policy_revision(self) -> str:
        revision = getattr(self.policy, "revision", None)
        return revision if isinstance(revision, str) and revision else "authority-default-deny"

    @staticmethod
    def _bounded(value: Any, maximum: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= maximum:
            raise AuthorityDenied("request.bounds", "authority duration is invalid")
        return float(value)

    @staticmethod
    def _peer_credentials(connection: socket.socket) -> tuple[int, int]:
        if not hasattr(socket, "SO_PEERCRED"):
            raise AuthorityDenied("peer.unavailable", "kernel peer credentials are unavailable")
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", raw)
        if pid <= 0 or uid <= 0:
            raise AuthorityDenied("peer.invalid", "root or invalid peer identity cannot request user authority")
        return pid, uid

    @staticmethod
    def _native_process_identity(peer_pid: int, peer_uid: int) -> str:
        """Hash kernel-observed executable inode and start time for a pinned PID."""
        try:
            stat_text = Path(f"/proc/{peer_pid}/stat").read_text(encoding="ascii")
            right = stat_text.rfind(")")
            fields = stat_text[right + 2:].split()
            # After the parenthesized comm, field 22 (starttime) is offset 19.
            start_ticks = fields[19]
            status = Path(f"/proc/{peer_pid}/status").read_text(encoding="ascii")
            uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
            real_uid = int(uid_line.split()[1])
            executable = os.stat(f"/proc/{peer_pid}/exe")
            if right < 0 or real_uid != peer_uid or not start_ticks.isdigit():
                raise ValueError("peer process identity mismatch")
            identity_hash = canonical_digest({
                "pid": peer_pid, "uid": real_uid, "start_ticks": start_ticks,
                "exe_device": executable.st_dev, "exe_inode": executable.st_ino,
            })
            return f"linux-proc:{identity_hash}"
        except (OSError, ValueError, StopIteration, IndexError):
            raise AuthorityDenied("peer.process", "kernel peer process identity is unavailable") from None

    @staticmethod
    def _read_json_line(connection: socket.socket, maximum: int) -> Any:
        data = bytearray()
        while len(data) <= maximum:
            chunk = connection.recv(1)
            if not chunk:
                break
            if chunk == b"\n":
                try:
                    return strict_json_loads(data.decode("ascii"))
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    raise AuthorityDenied("protocol.json", "authority request is malformed") from None
            data.extend(chunk)
        raise AuthorityDenied("protocol.bounds", "authority request is incomplete or oversized")

    @staticmethod
    def _write_json_line(connection: socket.socket, value: Mapping[str, Any], maximum: int) -> None:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        if len(data) > maximum:
            raise AuthorityDenied("protocol.bounds", "authority response exceeds its bound")
        connection.sendall(data)

    @staticmethod
    def _peer_disconnected(connection: socket.socket) -> bool:
        try:
            readable, _, _ = select.select([connection], [], [], 0)
            if not readable:
                return False
            return connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT) == b""
        except (BlockingIOError, InterruptedError):
            return False
        except OSError:
            return True
