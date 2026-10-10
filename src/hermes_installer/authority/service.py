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
    RootSelectedServiceContext, RootSelectedServiceEffectGrant, VerifiedRootSelectedServiceEffect,
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


class _RootDisplayReceiptSigner:
    """In-process Xauthority receipt signer with an isolated signature domain."""

    _DOMAIN = b"root-xauthority-startup-receipt-v1\x00"

    def __init__(self, service: "AuthorityService"):
        self._service = service

    def sign(self, payload: bytes) -> bytes:
        if not isinstance(payload, bytes) or len(payload) > 65_536:
            raise AuthorityDenied("display.receipt", "display receipt payload exceeds its bound")
        return hmac.new(self._service._key, self._DOMAIN + payload, hashlib.sha256).digest()

    def verify(self, payload: bytes, signature: bytes) -> bool:
        if (not isinstance(payload, bytes) or len(payload) > 65_536
                or not isinstance(signature, bytes) or len(signature) != hashlib.sha256().digest_size):
            return False
        return hmac.compare_digest(self.sign(payload), signature)


@dataclass(frozen=True, slots=True)
class RootEffectCompletionReceipt:
    """Root-private evidence for one fully validated, consumed host effect."""

    schema: int
    receipt_handle: str
    grant_id: str
    context_digest: str
    uid: int
    profile_id: str
    generation: str
    service_generation_digest: str
    operation: str
    target: str
    request_sha256: str
    response_status: int
    response_sha256: str
    response_size_bytes: int
    handler_receipt_id: str
    native_invocation_handle: str
    parent_source_receipt_handles: tuple[str, ...]
    parent_source_closure_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    signature: bytes

    def claims(self) -> dict[str, Any]:
        return {
            "schema": self.schema, "receipt_handle": self.receipt_handle,
            "grant_id": self.grant_id, "context_digest": self.context_digest,
            "uid": self.uid, "profile_id": self.profile_id, "generation": self.generation,
            "service_generation_digest": self.service_generation_digest,
            "operation": self.operation, "target": self.target,
            "request_sha256": self.request_sha256, "response_status": self.response_status,
            "response_sha256": self.response_sha256, "response_size_bytes": self.response_size_bytes,
            "handler_receipt_id": self.handler_receipt_id,
            "native_invocation_handle": self.native_invocation_handle,
            "parent_source_receipt_handles": self.parent_source_receipt_handles,
            "parent_source_closure_sha256": self.parent_source_closure_sha256,
            "issued_monotonic": self.issued_monotonic, "expires_monotonic": self.expires_monotonic,
        }

    def __post_init__(self) -> None:
        sha = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
        opaque = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
        if (self.schema != 1 or type(self.uid) is not int or self.uid < 0
                or type(self.response_status) is not int or not 0 <= self.response_status <= 599
                or type(self.response_size_bytes) is not int or not 0 <= self.response_size_bytes <= MAX_RESPONSE
                or any(not isinstance(value, str) or not value for value in (
                    self.profile_id, self.generation, self.operation, self.target))
                or any(not isinstance(value, str) or not sha.fullmatch(value) for value in (
                    self.context_digest, self.service_generation_digest, self.request_sha256,
                    self.response_sha256, self.parent_source_closure_sha256))
                or any(not isinstance(value, str) or not opaque.fullmatch(value) for value in (
                    self.receipt_handle, self.grant_id, self.native_invocation_handle))
                or not isinstance(self.handler_receipt_id, str) or not 1 <= len(self.handler_receipt_id) <= 256
                or not isinstance(self.parent_source_receipt_handles, tuple)
                or not self.parent_source_receipt_handles
                or any(not isinstance(value, str) or not opaque.fullmatch(value)
                       for value in self.parent_source_receipt_handles)
                or not isinstance(self.signature, bytes) or len(self.signature) != hashlib.sha256().digest_size
                or isinstance(self.issued_monotonic, bool) or not isinstance(self.issued_monotonic, (int, float))
                or not math.isfinite(self.issued_monotonic)
                or isinstance(self.expires_monotonic, bool) or not isinstance(self.expires_monotonic, (int, float))
                or not math.isfinite(self.expires_monotonic)
                or not self.issued_monotonic < self.expires_monotonic
                or self.expires_monotonic - self.issued_monotonic > MAX_EFFECT_LEASE):
            raise ValueError("root effect completion receipt is malformed")


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


class _ApplicationPackageObservationSigner:
    """Narrow public facade for the two source-owned v136 observations."""

    __slots__ = ("__service",)

    def __init__(self, service: "AuthorityService") -> None:
        self.__service = service

    def issue_locked_package_artifact(self, observation: Any) -> Any:
        return self.__service._issue_application_package_observation(
            "locked-package-artifact", observation)

    def verify_locked_package_artifact(self, receipt: Any) -> Any:
        return self.__service._verify_application_package_observation(
            "locked-package-artifact", receipt)

    def issue_package_license_observation(self, observation: Any) -> Any:
        return self.__service._issue_application_package_observation(
            "package-license", observation)

    def verify_package_license_observation(self, receipt: Any) -> Any:
        return self.__service._verify_application_package_observation(
            "package-license", receipt)


class _PublicInputPermissionSigner:
    """Narrow signer facade for the v138 public-web-read permission DTO."""

    __slots__ = ("__service",)

    def __init__(self, service: "AuthorityService") -> None:
        self.__service = service

    def issue_permission(self, permission: Any) -> Any:
        return self.__service._issue_public_input_permission(permission)

    def verify_permission(self, receipt: Any) -> Any:
        return self.__service._verify_public_input_permission(receipt)


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
        # Keep the exact root-loaded activation snapshot. Consent producers may
        # resolve an active profile by identifier, but must never provide a
        # PrincipalBinding (or enrollment row) of their own.
        self._active_binding_snapshot = dict(self.bindings_by_uid)
        self._active_profile_generation_snapshot = dict(self.profile_generations)
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
        self.channel_peer_delivery_registry = None
        self.native_turn_observation_registry = None
        self.native_channel_context_store = None
        self._root_channel_delivery_token = object()
        self._root_channel_input_deliveries: dict[int, Any] = {}
        self._root_channel_source_registrations: dict[int, Any] = {}
        self._root_channel_context_registrations: dict[int, Any] = {}
        self.private_input_consent_registry = None
        self.memory_capture_consent_registry = None
        self.native_mcp_dispatcher = None
        self.selected_application_router = None
        self.private_memory_route_resolver = None
        self.private_memory_job_queue = None
        self.private_memory_observation_producer = None
        self.application_package_observation_producer = None
        self._application_package_observation_signer = None
        self.public_input_permission_registry = None
        self._public_input_permission_signer = None
        self.web_content_artifact_registry = None
        self.memory_step_effect_authority = memory_step_effect_authority
        self.resource_task_runner = None
        self.resource_job_authority = None
        self.resource_task_authority = None
        self.resource_event_context_issuer = None
        self.root_selected_startup_authority = None
        self.root_selected_memory_authority = None
        self._root_selected_service_effects: dict[str, dict[str, Any]] = {}
        self._root_selected_nonce_states: dict[str, tuple[str, float]] = {}
        self._root_selected_seal = object()
        self._root_effect_completion_receipts: dict[str, dict[str, Any]] = {}
        if (service_generation_digest is not None
                and not re.fullmatch(r"[0-9a-f]{64}", service_generation_digest)):
            raise ValueError("active service generation digest is invalid")
        self.service_generation_digest = service_generation_digest
        self.root_runtime_bindings = None
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

    def attach_root_runtime_bindings(self, bindings: Any) -> None:
        """Attach the exact typed root composition used to resolve active rows."""
        from .runtime_bindings import RootRuntimeBindings

        if (self.root_runtime_bindings is not None
                or type(bindings) is not RootRuntimeBindings
                or getattr(getattr(bindings, "enrollment_catalog", None), "digest", None)
                != self.service_generation_digest
                or (self.process_effect_handler is not None
                    and bindings.process_manager is not self.process_effect_handler)
                or len(bindings.protected_principal_bindings) != len(self.bindings_by_uid)
                or any(all(item is not current for item in bindings.protected_principal_bindings)
                       for current in self.bindings_by_uid.values())):
            raise AuthorityDenied("authority.composition", "root runtime binding is not this active protected generation")
        self.root_runtime_bindings = bindings

    def attach_private_memory_effect_runtime(self, job_queue: Any, route_resolver: Any) -> None:
        """Attach the root-owned queue and protected private-route resolver once."""
        from hermes_installer.memory.broker import DurableMemoryQueue, ProfiledMemoryJobResolver
        from hermes_installer.providers.private_memory import RootPrivateMemoryRouteResolver

        if (self.private_memory_job_queue is not None or self.private_memory_route_resolver is not None
                or type(job_queue) not in (DurableMemoryQueue, ProfiledMemoryJobResolver)
                or type(route_resolver) is not RootPrivateMemoryRouteResolver
                or getattr(route_resolver, "effect_broker", None) is not self
                or getattr(route_resolver, "bindings", None) is not self.root_runtime_bindings
                or self.root_runtime_bindings is None
                or not callable(getattr(job_queue, "resolve_active_job", None))
                or not callable(getattr(job_queue, "is_current", None))):
            raise AuthorityDenied("memory.provider", "root private memory effect runtime is not this active composition")
        self.private_memory_job_queue = job_queue
        self.private_memory_route_resolver = route_resolver

    def attach_private_memory_observation_producer(self, registry: Any) -> None:
        """Attach the exact root journal-backed observation registry once."""
        from hermes_installer.models.private_deployment import RootPrivateMemoryDeploymentRegistry

        if (self.private_memory_observation_producer is not None
                or type(registry) is not RootPrivateMemoryDeploymentRegistry
                or getattr(registry, "authority_service", None) is not self
                or not callable(getattr(registry, "verify_observation_for_authority", None))
                or not callable(getattr(registry, "retain_authority_signed_observation", None))
                or not callable(getattr(registry, "verify_observation_receipt", None))):
            raise AuthorityDenied("memory.observation", "root private-memory observation registry is not this authority composition")
        self.private_memory_observation_producer = registry

    def issue_private_memory_observation(self, observation_kind: str,
                                         verified_root_observation: Any) -> Any:
        """Sign and durably retain one root-verified private-memory observation."""
        from dataclasses import replace
        from hermes_installer.models.private_deployment import (
            ExistingModelArtifactObservation, PrivateEndpointObservation,
            PrivateModelDeploymentObservation,
        )

        contract = {
            "existing-model-tree": (ExistingModelArtifactObservation, "root-existing-model-tree-v1"),
            "private-endpoint": (PrivateEndpointObservation, "root-private-endpoint-v1"),
            "private-model-deployment": (PrivateModelDeploymentObservation,
                                         "root-private-model-deployment-v1"),
        }
        expected = contract.get(observation_kind) if isinstance(observation_kind, str) else None
        registry = self.private_memory_observation_producer
        if (registry is None or expected is None or type(verified_root_observation) is not expected[0]
                or not callable(getattr(verified_root_observation, "claims", None))):
            raise AuthorityDenied("memory.observation", "private-memory observation kind or source type is unavailable")
        try:
            if not registry.verify_observation_for_authority(observation_kind, verified_root_observation):
                raise AuthorityDenied("memory.observation", "private-memory source observation is not current")
            claims = verified_root_observation.claims()
            if not isinstance(claims, Mapping) or not claims:
                raise AuthorityDenied("memory.observation", "private-memory observation claims are invalid")
            signature = bytes.fromhex(self._sign_root_selected(expected[1], claims))
            receipt = replace(verified_root_observation, signature=signature)
            registry.retain_authority_signed_observation(observation_kind, receipt)
            return receipt
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("memory.observation", "private-memory observation could not be signed and retained") from None

    def verify_private_memory_observation(self, receipt: Any) -> Any:
        """Verify both the kind-specific signature and live retained registry proof."""
        from hermes_installer.models.private_deployment import (
            ExistingModelArtifactObservation, PrivateEndpointObservation,
            PrivateModelDeploymentObservation,
        )

        registry = self.private_memory_observation_producer
        contract = (
            (ExistingModelArtifactObservation, "existing-model-tree", "root-existing-model-tree-v1"),
            (PrivateEndpointObservation, "private-endpoint", "root-private-endpoint-v1"),
            (PrivateModelDeploymentObservation, "private-model-deployment",
             "root-private-model-deployment-v1"),
        )
        matched = next((row for row in contract if type(receipt) is row[0]), None)
        if registry is None or matched is None or not callable(getattr(receipt, "claims", None)):
            raise AuthorityDenied("memory.observation", "private-memory observation receipt type is invalid")
        try:
            if (not isinstance(receipt.signature, bytes)
                    or len(receipt.signature) != hashlib.sha256().digest_size):
                raise AuthorityDenied("memory.observation", "private-memory observation signature is malformed")
            self._verify_root_selected_signature(matched[2], receipt.claims(), receipt.signature.hex())
            if not registry.verify_observation_receipt(receipt):
                raise AuthorityDenied("memory.observation", "private-memory observation is stale or unretained")
            return receipt
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("memory.observation", "private-memory observation verification failed") from None

    def attach_application_package_closure_registry(self, registry: Any) -> None:
        """Attach the exact root-owned locked-package observation registry."""
        from .application_runtime_preparation import RootApplicationOfflinePackageClosureRegistry

        if (self.application_package_observation_producer is not None
                or type(registry) is not RootApplicationOfflinePackageClosureRegistry
                or getattr(registry, "authority_service", None) is not self
                or not callable(getattr(registry, "verify_observation_for_authority", None))
                or not callable(getattr(registry, "retain_authority_signed_observation", None))
                or not callable(getattr(registry, "verify_observation_receipt", None))):
            raise AuthorityDenied("application.package_observation", "root package observation registry is invalid")
        self.application_package_observation_producer = registry

    def application_package_observation_signer(self) -> Any:
        """Return the service-owned signer scoped to two exact v136 DTOs."""
        if self._application_package_observation_signer is None:
            self._application_package_observation_signer = _ApplicationPackageObservationSigner(self)
        return self._application_package_observation_signer

    def _issue_application_package_observation(self, kind: str, observation: Any) -> Any:
        from dataclasses import replace
        from .application_runtime_preparation import (
            RootApplicationLockedPackageArtifactReceipt,
            RootApplicationPackageLicenseObservation,
        )

        specs = {
            "locked-package-artifact": (
                RootApplicationLockedPackageArtifactReceipt,
                "root-application-locked-package-artifact-v136",
                frozenset({
                    "receipt_handle", "artifact_id", "application_id",
                    "source_preparation_selection_handle", "qualification_choice_handle",
                    "qualification_consent_receipt_handle", "setup_session_id", "transaction_handle",
                    "plan_sha256", "prepared_generation_digest", "lock_receipt_handle", "lock_sha256",
                    "lock_member_id", "package_name", "package_version", "artifact_kind",
                    "platform_tags", "origin_policy_id", "source_url", "lock_integrity_algorithm",
                    "lock_integrity_digest", "artifact_sha256", "size_bytes", "cas_device",
                    "cas_inode", "cas_mode", "controller_binding_handle", "issued_monotonic",
                    "expires_monotonic",
                }),
            ),
            "package-license": (
                RootApplicationPackageLicenseObservation,
                "root-application-package-license-observation-v136",
                frozenset({
                    "receipt_handle", "artifact_receipt_handle", "artifact_sha256", "package_name",
                    "package_version", "metadata_kind", "metadata_member_path",
                    "metadata_member_sha256", "declared_license_expression", "license_member_records",
                    "evidence_sha256", "eligibility", "review_policy_receipt_handle",
                    "issued_monotonic", "expires_monotonic",
                }),
            ),
        }
        spec = specs.get(kind)
        registry = self.application_package_observation_producer
        if (spec is None or registry is None or type(observation) is not spec[0]
                or not callable(getattr(observation, "claims", None))):
            raise AuthorityDenied("application.package_observation", "package observation kind or source type is unavailable")
        try:
            if registry.verify_observation_for_authority(kind, observation) is not True:
                raise AuthorityDenied("application.package_observation", "package source evidence is not current")
            claims = observation.claims()
            if not isinstance(claims, Mapping) or set(claims) != spec[2]:
                raise AuthorityDenied("application.package_observation", "package observation claims differ from v136 schema")
            receipt = replace(observation, signature=self._sign_root_selected(spec[1], claims))
            if registry.retain_authority_signed_observation(kind, receipt) is not True:
                raise AuthorityDenied("application.package_observation", "package receipt was not retained")
            return receipt
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("application.package_observation", "package observation could not be signed and retained") from None

    def _verify_application_package_observation(self, kind: str, receipt: Any) -> Any:
        from .application_runtime_preparation import (
            RootApplicationLockedPackageArtifactReceipt,
            RootApplicationPackageLicenseObservation,
        )

        specs = {
            "locked-package-artifact": (RootApplicationLockedPackageArtifactReceipt,
                                         "root-application-locked-package-artifact-v136"),
            "package-license": (RootApplicationPackageLicenseObservation,
                                "root-application-package-license-observation-v136"),
        }
        registry = self.application_package_observation_producer
        spec = specs.get(kind)
        if (registry is None or spec is None or type(receipt) is not spec[0]
                or not isinstance(getattr(receipt, "signature", None), str)
                or len(receipt.signature) != hashlib.sha256().digest_size * 2):
            raise AuthorityDenied("application.package_observation", "package observation receipt type is invalid")
        try:
            claims = receipt.claims()
            expected_claims = set(receipt.__dataclass_fields__) - {"signature"}
            if not isinstance(claims, Mapping) or set(claims) != expected_claims:
                raise AuthorityDenied("application.package_observation", "package receipt claims differ from its typed schema")
            self._verify_root_selected_signature(spec[1], claims, receipt.signature)
            if registry.verify_observation_receipt(receipt) is not True:
                raise AuthorityDenied("application.package_observation", "package observation is stale or unretained")
            return receipt
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("application.package_observation", "package observation could not be verified") from None

    def attach_root_public_input_permission_registry(self, registry: Any) -> None:
        """Attach the exact durable public-input permission registry once."""
        from .root_public_input_permission import RootPublicInputPermissionRegistry

        if (self.public_input_permission_registry is not None
                or type(registry) is not RootPublicInputPermissionRegistry
                or getattr(registry, "service", None) is not self
                or not callable(getattr(registry, "verify_observation_for_authority", None))
                or not callable(getattr(registry, "retain_authority_signed_observation", None))
                or not callable(getattr(registry, "verify_permission_membership", None))):
            raise AuthorityDenied("source.public_permission", "root public-input permission registry is invalid")
        self.public_input_permission_registry = registry

    def root_public_input_permission_signer(self) -> Any:
        """Return the only signer for the exact v138 public-input permission DTO."""
        if self._public_input_permission_signer is None:
            self._public_input_permission_signer = _PublicInputPermissionSigner(self)
        return self._public_input_permission_signer

    def _issue_public_input_permission(self, permission: Any) -> Any:
        from dataclasses import replace
        from .root_public_input_permission import RootPublicInputPermission

        registry = self.public_input_permission_registry
        expected_claims = frozenset({
            "receipt_handle", "consent_id", "purpose", "selection_handle",
            "principal_id", "profile_id", "namespace_id", "profile_generation",
            "service_generation_digest", "retained_input_selection_handle",
            "input_observation_handle", "input_sha256", "web_scope_ids",
            "web_scope_sha256", "public_recipient_ids", "allowed_operations",
            "additional_metered_budget_usd", "revocation_epoch", "issued_monotonic",
            "expires_monotonic",
        })
        if (registry is None or type(permission) is not RootPublicInputPermission
                or not callable(getattr(permission, "claims", None))):
            raise AuthorityDenied("source.public_permission", "public-input permission candidate is unavailable")
        try:
            if registry.verify_observation_for_authority(permission) is not True:
                raise AuthorityDenied("source.public_permission", "public-input observation or selection is not current")
            claims = permission.claims()
            if not isinstance(claims, Mapping) or set(claims) != expected_claims:
                raise AuthorityDenied("source.public_permission", "public-input permission claims differ from v138 schema")
            now = self.monotonic()
            if (permission.purpose != "public-free-web-read"
                    or permission.allowed_operations != ("plugin.web.read",)
                    or isinstance(permission.additional_metered_budget_usd, bool)
                    or not isinstance(permission.additional_metered_budget_usd, (int, float))
                    or permission.additional_metered_budget_usd != 0.0
                    or isinstance(permission.issued_monotonic, bool)
                    or not isinstance(permission.issued_monotonic, (int, float))
                    or isinstance(permission.expires_monotonic, bool)
                    or not isinstance(permission.expires_monotonic, (int, float))
                    or not math.isfinite(permission.issued_monotonic)
                    or not math.isfinite(permission.expires_monotonic)
                    or not permission.issued_monotonic <= now < permission.expires_monotonic
                    or permission.expires_monotonic - permission.issued_monotonic > 30.0):
                raise AuthorityDenied("source.public_permission", "public-input permission exceeds its fixed purpose")
            signed = replace(permission, signature=self._sign_root_selected(
                "root-public-input-permission-v138", claims))
            if registry.retain_authority_signed_observation(signed) is not True:
                raise AuthorityDenied("source.public_permission", "signed public-input permission was not retained")
            return signed
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("source.public_permission", "public-input permission could not be signed and retained") from None

    def _verify_public_input_permission(self, receipt: Any) -> Any:
        from .root_public_input_permission import RootPublicInputPermission

        registry = self.public_input_permission_registry
        if (registry is None or type(receipt) is not RootPublicInputPermission
                or not isinstance(getattr(receipt, "signature", None), str)
                or len(receipt.signature) != hashlib.sha256().digest_size * 2
                or not callable(getattr(receipt, "claims", None))):
            raise AuthorityDenied("source.public_permission", "public-input permission receipt type is invalid")
        try:
            claims = receipt.claims()
            expected_claims = {
                "receipt_handle", "consent_id", "purpose", "selection_handle",
                "principal_id", "profile_id", "namespace_id", "profile_generation",
                "service_generation_digest", "retained_input_selection_handle",
                "input_observation_handle", "input_sha256", "web_scope_ids",
                "web_scope_sha256", "public_recipient_ids", "allowed_operations",
                "additional_metered_budget_usd", "revocation_epoch", "issued_monotonic",
                "expires_monotonic",
            }
            if (not isinstance(claims, Mapping)
                    or set(claims) != expected_claims):
                raise AuthorityDenied("source.public_permission", "public-input permission claims differ from typed schema")
            self._verify_root_selected_signature(
                "root-public-input-permission-v138", claims, receipt.signature)
            if registry.verify_permission_membership(receipt) is not True:
                raise AuthorityDenied("source.public_permission", "public-input permission is stale or unretained")
            return receipt
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("source.public_permission", "public-input permission could not be verified") from None

    def attach_web_content_artifact_registry(self, registry: Any) -> None:
        """Attach the exact staged web-content CAS/receipt owner once."""
        from .web_content_artifacts import RootWebContentArtifactRegistry

        if (self.web_content_artifact_registry is not None
                or type(registry) is not RootWebContentArtifactRegistry
                or getattr(registry, "service", None) is not self
                or not callable(getattr(registry, "resolve_staged_effect", None))
                or not callable(getattr(registry, "finalize_authorized_effect", None))):
            raise AuthorityDenied("web.content", "root web-content artifact registry is not this authority composition")
        self.web_content_artifact_registry = registry

    def verify_root_effect_completion(self, receipt: Any, *, context: HostContext,
                                      authorization: EffectAuthorization, operation: str,
                                      target: str, request_payload: bytes,
                                      response_status: int, response_body: bytes,
                                      handler_receipt_id: str) -> bool:
        """Check a service-minted effect completion against its one-use retained execution."""
        if type(receipt) is not RootEffectCompletionReceipt:
            return False
        try:
            self._verify_root_selected_signature(
                "root-effect-completion-v1", receipt.claims(), receipt.signature.hex())
            with self._lock:
                entry = self._root_effect_completion_receipts.get(receipt.receipt_handle)
                if (entry is None or entry["receipt"] is not receipt
                        or entry["state"] not in {"issued", "finalized"}):
                    return False
                if entry["authority_epoch"] != self.authority_epoch:
                    return False
            if (not isinstance(context, HostContext) or not isinstance(authorization, EffectAuthorization)
                    or not isinstance(request_payload, bytes) or not isinstance(response_body, bytes)
                    or type(response_status) is not int or not isinstance(handler_receipt_id, str)):
                return False
            self._verify_context_signature(context)
            self._verify_grant_signature(authorization)
            self._assert_current_context(context, self._binding(context.uid), context.uid)
            self._assert_grant_current(authorization, self._binding(context.uid), context.uid)
            if (receipt.grant_id != authorization.grant_id
                    or receipt.context_digest != _context_digest(context)
                    or receipt.uid != context.uid or receipt.profile_id != context.profile_id
                    or receipt.generation != context.generation
                    or receipt.service_generation_digest != self.service_generation_digest
                    or receipt.operation != operation or receipt.target != target
                    or receipt.request_sha256 != hashlib.sha256(request_payload).hexdigest()
                    or receipt.request_sha256 != authorization.request_digest
                    or receipt.response_status != response_status
                    or receipt.response_sha256 != hashlib.sha256(response_body).hexdigest()
                    or receipt.response_size_bytes != len(response_body)
                    or receipt.handler_receipt_id != handler_receipt_id
                    or receipt.parent_source_closure_sha256 != context.lineage_hash
                    or receipt.parent_source_receipt_handles != entry["source_handles"]
                    or receipt.native_invocation_handle != entry["invocation"].native_invocation_handle
                    or receipt.expires_monotonic <= self.monotonic()
                    or authorization.nonce not in self._nonces
                    or self._nonces[authorization.nonce] <= self.monotonic()):
                return False
            return True
        except Exception:
            return False

    def _mint_root_effect_completion(self, *, context: HostContext,
                                     authorization: EffectAuthorization, operation: str,
                                     target: str, request_payload: bytes, response_status: int,
                                     response_body: bytes, handler_receipt_id: str,
                                     invocation: Any) -> RootEffectCompletionReceipt:
        from .web_content_artifacts import VerifiedRootWebResponseObservation

        if (type(invocation) is not VerifiedRootWebResponseObservation
                or invocation.canonical_request_sha256 != authorization.request_digest
                or invocation.profile_id != context.profile_id
                or invocation.owner_generation != context.generation
                or invocation.expires_monotonic <= self.monotonic()
                or not isinstance(request_payload, bytes)
                or hashlib.sha256(request_payload).hexdigest() != authorization.request_digest
                or not isinstance(response_body, bytes) or not 200 <= response_status < 300
                or not isinstance(handler_receipt_id, str) or not 1 <= len(handler_receipt_id) <= 256):
            raise AuthorityDenied("effect.completion", "validated web effect completion is not joined")
        source_by_id: dict[str, str] = {}
        with self._lock:
            for handle, source_receipt in self._source_receipt_handles.items():
                if source_receipt.monotonic_expires_at > self.monotonic():
                    source_by_id[source_receipt.receipt_id] = handle
        receipt_ids = tuple(item.receipt_id for item in context.source_receipts)
        if (not receipt_ids or any(receipt_id not in source_by_id for receipt_id in receipt_ids)):
            raise AuthorityDenied("effect.completion", "root source closure is not retained")
        source_handles = tuple(source_by_id[receipt_id] for receipt_id in receipt_ids)
        if (source_handles != invocation.parent_source_receipt_handles
                or not isinstance(invocation.native_invocation_handle, str)):
            raise AuthorityDenied("effect.completion", "native invocation does not bind the exact source closure")
        now = self.monotonic()
        expires = min(now + 30.0, authorization.monotonic_expires_at, invocation.expires_monotonic)
        claims = {
            "schema": 1, "receipt_handle": secrets.token_urlsafe(32),
            "grant_id": authorization.grant_id, "context_digest": _context_digest(context),
            "uid": context.uid, "profile_id": context.profile_id, "generation": context.generation,
            "service_generation_digest": self.service_generation_digest,
            "operation": operation, "target": target,
            "request_sha256": hashlib.sha256(request_payload).hexdigest(),
            "response_status": response_status,
            "response_sha256": hashlib.sha256(response_body).hexdigest(),
            "response_size_bytes": len(response_body), "handler_receipt_id": handler_receipt_id,
            "native_invocation_handle": invocation.native_invocation_handle,
            "parent_source_receipt_handles": source_handles,
            "parent_source_closure_sha256": context.lineage_hash,
            "issued_monotonic": now, "expires_monotonic": expires,
        }
        if expires <= now:
            raise AuthorityDenied("effect.completion", "effect completion lease expired")
        signature = bytes.fromhex(self._sign_root_selected("root-effect-completion-v1", claims))
        receipt = RootEffectCompletionReceipt(**claims, signature=signature)
        with self._lock:
            if authorization.nonce in self._nonces or receipt.receipt_handle in self._root_effect_completion_receipts:
                raise AuthorityDenied("effect.completion", "effect completion is replayed")
            self._root_effect_completion_receipts[receipt.receipt_handle] = {
                "receipt": receipt, "invocation": invocation, "source_handles": source_handles,
                "authority_epoch": self.authority_epoch, "state": "issued",
            }
        return receipt

    def _finalize_web_content_effect(self, *, context: HostContext,
                                     authorization: EffectAuthorization, operation: str,
                                     target: str, request_payload: bytes,
                                     response_status: int, response_body: bytes,
                                     handler_receipt_id: str) -> Any:
        """Finalize staged web bytes only after the handler response is validated."""
        from .web_content_artifacts import RootWebContentArtifactReceipt, VerifiedRootWebResponseObservation

        registry = self.web_content_artifact_registry
        if registry is None or operation != "plugin.web.read" or not 200 <= response_status < 300:
            raise AuthorityDenied("web.content", "root web content finalizer is unavailable")
        try:
            observation = registry.resolve_staged_effect(
                context=context, authorization=authorization, operation=operation, target=target,
                request_payload=request_payload, response_status=response_status,
                response_body=response_body, effect_receipt_id=handler_receipt_id,
            )
            from .native_runtime_observer import RootNativeToolEffectInvocation
            invocation_registry = self.native_invocation_registry
            resolve_current_invocation = getattr(
                invocation_registry, "resolve_current_invocation_for_effect", None)
            staged_invocation = getattr(observation, "_invocation", None)
            if (type(observation) is not VerifiedRootWebResponseObservation
                    or observation.canonical_request_sha256 != authorization.request_digest
                    or observation.profile_id != context.profile_id
                    or observation.owner_generation != context.generation
                    or observation.body_sha256 != hashlib.sha256(response_body).hexdigest()
                    or observation.body_size_bytes != len(response_body)
                    or not callable(resolve_current_invocation)
                    or type(staged_invocation) is not RootNativeToolEffectInvocation
                    or observation.parent_source_receipt_handles == ()):
                raise AuthorityDenied("web.content", "staged web observation does not bind validated effect")
            current_invocation = resolve_current_invocation(
                context, authorization, operation, target, authorization.request_digest,
                staged_invocation.invocation_handle,
            )
            if (type(current_invocation) is not RootNativeToolEffectInvocation
                    or current_invocation != staged_invocation
                    or current_invocation.profile_id != context.profile_id
                    or current_invocation.generation != context.generation
                    or current_invocation.service_generation_digest != self.service_generation_digest
                    or current_invocation.operation != operation
                    or current_invocation.request_digest != authorization.request_digest
                    or current_invocation.source_receipt_handles
                       != observation.parent_source_receipt_handles):
                raise AuthorityDenied("web.content", "staged native invocation is no longer current")
            completion = self._mint_root_effect_completion(
                context=context, authorization=authorization, operation=operation, target=target,
                request_payload=request_payload, response_status=response_status,
                response_body=response_body, handler_receipt_id=handler_receipt_id,
                invocation=current_invocation,
            )
            if not self.verify_root_effect_completion(
                    completion, context=context, authorization=authorization, operation=operation,
                    target=target, request_payload=request_payload, response_status=response_status,
                    response_body=response_body, handler_receipt_id=handler_receipt_id):
                raise AuthorityDenied("web.content", "root effect completion receipt failed currentness")
            receipt = registry.finalize_authorized_effect(observation, completion, response_body)
            if type(receipt) is not RootWebContentArtifactReceipt:
                raise AuthorityDenied("web.content", "root web artifact finalizer returned an invalid receipt")
            with self._lock:
                entry = self._root_effect_completion_receipts.get(completion.receipt_handle)
                if entry is None or entry["receipt"] is not completion or entry["state"] != "issued":
                    raise AuthorityDenied("web.content", "root effect completion was already consumed")
                entry["state"] = "finalized"
            return receipt
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("web.content", "staged web content could not be finalized") from None

    def dispatch_private_memory_model(self, job_handle: str, payload: bytes, timeout: float,
                                      cancelled: Callable[[], bool]) -> bytes:
        """Dispatch one selected private memory model attempt through HI12.

        The worker-facing memory engine supplies only its opaque durable job
        handle and canonical body. All source, consent, route, target and model
        bindings are resolved again here from root-owned registries.
        """
        import base64
        import hashlib
        from hermes_installer.memory.broker import MemoryJobAuthorityRecord
        from hermes_installer.providers.private_memory import PrivateMemoryDispatchSelection

        queue = self.private_memory_job_queue
        resolver = self.private_memory_route_resolver
        if (queue is None or resolver is None or not isinstance(job_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", job_handle)
                or not isinstance(payload, bytes) or not payload or len(payload) > 1_114_112
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 120
                or not callable(cancelled) or cancelled()):
            raise AuthorityDenied("memory.provider", "private memory effect inputs are invalid or unavailable")
        try:
            record = queue.resolve_active_job(job_handle, now=self.monotonic())
            if type(record) is not MemoryJobAuthorityRecord or record.job_handle != job_handle:
                raise AuthorityDenied("memory.provider", "active durable memory job proof is invalid")
            source_wire = self._decode_wire(record.source_context_wire, "memory source context")
            source = HostContext.from_wire(source_wire)
            self._verify_context_signature(source)
            if (source.profile_id != record.profile_id or source.namespace_id != record.namespace_id
                    or source.lineage_hash != record.source_closure_sha256
                    or tuple(receipt.receipt_id for receipt in source.source_receipts)
                       != record.source_receipt_handles):
                raise AuthorityDenied("memory.provider", "durable source identity is inconsistent")
            consent_wire = self._decode_wire(record.consent_wire, "memory background consent")
            if (not isinstance(consent_wire, dict)
                    or consent_wire.get("consent_id") != record.consent_id):
                raise AuthorityDenied("memory.provider", "durable background consent identity is inconsistent")
            parsed = strict_json_loads(payload.decode("utf-8", errors="strict"))
            if not isinstance(parsed, Mapping):
                raise AuthorityDenied("memory.provider", "private model request must be a canonical object")
            if canonical_bytes(parsed) != payload or not isinstance(parsed.get("model"), str):
                raise AuthorityDenied("memory.provider", "private model request is not canonical or model-bound")
            selected = resolver.resolve_dispatch_selection(job_handle, payload)
            if type(selected) is not PrivateMemoryDispatchSelection:
                raise AuthorityDenied("memory.provider", "protected private dispatch selection is invalid")
            action = selected.action
            route_capability = "text-generation" if action == "extract" else "embedding"
            memory_enrollment = self.root_runtime_bindings.resolve_memory_enrollment(
                selected.memory_enrollment_id,
                service_generation_digest=self.service_generation_digest,
            )
            capture_claims = consent_wire
            required_capture_fields = {
                "capture_consent_handle", "capture_consent_receipt_handle", "capture_consent_id",
                "capture_consent_revocation_epoch", "capture_consent_policy_revision",
                "completed_turn_receipt_handle",
            }
            if not required_capture_fields.issubset(capture_claims):
                raise AuthorityDenied("memory.provider", "durable job lacks persistent capture opt-in linkage")

            def capture_opt_in_is_current() -> bool:
                try:
                    from .root_memory_capture_consent import (
                        RootMemoryCaptureConsent, RootMemoryCaptureConsentRegistry,
                    )
                    registry = self.memory_capture_consent_registry
                    if type(registry) is not RootMemoryCaptureConsentRegistry:
                        return False
                    current = registry.resolve_capture_consent(
                        capture_claims["capture_consent_handle"],
                        completed_turn_receipt_handle=capture_claims["completed_turn_receipt_handle"],
                        selected_memory_binding=memory_enrollment,
                    )
                    return (type(current) is RootMemoryCaptureConsent
                            and current.state == "enabled"
                            and current.receipt_handle == capture_claims["capture_consent_receipt_handle"]
                            and current.consent_id == capture_claims["capture_consent_id"]
                            and current.revocation_epoch == capture_claims["capture_consent_revocation_epoch"]
                            and current.policy_revision == capture_claims["capture_consent_policy_revision"]
                            and current.profile_id == record.profile_id
                            and current.namespace_id == record.namespace_id
                            and current.principal_id == source.principal_id
                            and current.provider == record.provider
                            and current.memory_owner_generation == record.owner_generation
                            and current.revocation_epoch > 0)
                except Exception:
                    return False

            if (action not in {"extract", "embed"}
                    or selected.purpose != ("memory-extraction" if action == "extract" else "memory-embedding")
                    or selected.stage_operation != f"memory.{action}"
                    or selected.operation != "provider.dispatch"
                    or selected.capability != "provider-inference"
                    or selected.selected.profile_id != record.profile_id
                    or selected.selected.namespace_id != record.namespace_id
                    or selected.selected.memory_provider != record.provider
                    or selected.selected.memory_owner_generation != record.owner_generation
                    or selected.selected.service_generation_digest != self.service_generation_digest
                    or selected.memory_enrollment_id != memory_enrollment.service_enrollment_id
                    or memory_enrollment.profile_id != record.profile_id
                    or memory_enrollment.namespace_identity != record.namespace_id
                    or memory_enrollment.provider != record.provider
                    or memory_enrollment.memory_owner_generation != record.owner_generation
                    or selected.route.recipient_id != selected.recipient
                    or selected.route.effect_target != selected.target
                    or selected.route.additional_metered_budget_usd != 0
                    or selected.route.capability != route_capability
                    or selected.deployment.served_model_id != parsed["model"]
                    or selected.deployment.capability != route_capability
                    or selected.selected.expires_monotonic <= self.monotonic()
                    or not resolver.is_current(selected.selected)
                    or not capture_opt_in_is_current()):
                raise AuthorityDenied("memory.provider", "current private job, route, deployment or budget does not join")
            binding = self._binding(source.uid)
            if (binding.profile_id != record.profile_id or binding.namespace_id != record.namespace_id
                    or record.provider != selected.selected.memory_provider
                    or self.memory_owner_state is None
                    or self.memory_owner_state(record.profile_id) != (record.provider, record.owner_generation)):
                raise AuthorityDenied("memory.provider", "current memory owner or source principal changed")
            stage_context = self.context_for_job(
                record.source_context_wire, record.consent_wire, provider_id=record.provider,
                owner_generation=record.owner_generation, action=action,
                lease_seconds=min(30.0, max(0.1, record.lease_until - self.monotonic())),
                final_payload_digest=hashlib.sha256(payload).hexdigest(),
            )
            if (stage_context.sensitivity not in {Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN}
                    or stage_context.profile_id != record.profile_id
                    or stage_context.namespace_id != record.namespace_id
                    or tuple(receipt.receipt_id for receipt in stage_context.source_receipts)
                       != record.source_receipt_handles):
                raise AuthorityDenied("memory.provider", "fresh source-derived context lost private ancestry")
            child_wire = self._issue_context(source.uid, {
                "purpose": selected.purpose,
                "intent": f"private-memory-provider:{record.provider}:{action}:{record.source_closure_sha256}",
                "trace_id": stage_context.trace_id,
                "lease_seconds": min(30.0, max(0.1, record.lease_until - self.monotonic())),
                "source_contexts": [stage_context.to_wire()],
                "final_payload_digest": hashlib.sha256(payload).hexdigest(),
                "operation": "provider.dispatch",
            }, allow_expired_sources=True,
               inherited_process_identity=source.native_process_identity)
            context = HostContext.from_wire(child_wire)
            rule = self.rules.get((selected.capability, "provider.dispatch", selected.target))
            if (rule is None or rule.recipient != selected.recipient
                    or (rule.operation, rule.target) not in self.handlers
                    or selected.capability not in binding.capabilities
                    or not self.policy.allow_effect(context=context, rule=rule,
                                                   request_digest=hashlib.sha256(payload).hexdigest(),
                                                   retry_index=record.attempt - 1)):
                raise AuthorityDenied("memory.provider", "selected private provider effect is not enrolled")
            digest = hashlib.sha256(payload).hexdigest()
            authorization = self._authorize_effect(source.uid, {
                "context": context.to_wire(), "capability": selected.capability,
                "target": selected.target, "recipient": selected.recipient,
                "request_digest": digest, "retry_index": record.attempt - 1,
            })
            remaining = min(float(timeout), record.lease_until - self.monotonic(),
                             selected.selected.expires_monotonic - self.monotonic(),
                             context.monotonic_expires_at - self.monotonic())
            if (remaining <= 0 or cancelled() or not queue.is_current(record, now=self.monotonic())
                    or not resolver.is_current(selected.selected)):
                raise AuthorityDenied("memory.provider", "private model attempt expired or was revoked before dispatch")

            def still_current() -> bool:
                try:
                    if cancelled() or not queue.is_current(record, now=self.monotonic()):
                        return False
                    if self.memory_owner_state is None or self.memory_owner_state(record.profile_id) != (
                            record.provider, record.owner_generation):
                        return False
                    if not resolver.is_current(selected.selected):
                        return False
                    if not capture_opt_in_is_current():
                        return False
                    current_context = self.context_for_job(
                        record.source_context_wire, record.consent_wire, provider_id=record.provider,
                        owner_generation=record.owner_generation, action=action,
                        lease_seconds=min(30.0, max(0.1, record.lease_until - self.monotonic())),
                        final_payload_digest=digest,
                    )
                    return (current_context.lineage_hash == record.source_closure_sha256
                            and current_context.profile_id == context.profile_id
                            and current_context.namespace_id == context.namespace_id)
                except Exception:
                    return False

            if not still_current():
                raise AuthorityDenied("memory.provider", "private model source or consent became stale")
            result = self._perform_effect(source.uid, os.getpid(), {
                "authorization": authorization, "operation": "provider.dispatch",
                "payload": base64.b64encode(payload).decode("ascii"), "timeout": remaining,
            }, cancelled=lambda: not still_current(), enforce_peer_identity=False)
            body = base64.b64decode(result["body"], validate=True)
            if len(body) > 2_097_152:
                raise AuthorityDenied("memory.provider", "private model response exceeded its fixed bound")
            if not still_current():
                raise AuthorityDenied("memory.provider", "private model result arrived after job or consent revocation")
            return body
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("memory.provider", "active durable job or signed source closure is invalid") from None


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

    def authorize_completed_memory_turn(
        self, record: Any, *, enrollment: Any, transcript_sha256: str,
        background_consent_handle: str, owner_generation: int,
    ) -> tuple[HostContext, BackgroundConsent]:
        """Issue a fresh PRIVATE memory-capture context from one retained turn.

        This is a root-only coordinator call. The native turn registry must
        still retain the exact completion object; the service then verifies
        the complete signed source-receipt closure and the separate durable
        capture opt-in before issuing per-job consent.
        """
        from ..memory.enrollment import MemoryServiceEnrollment
        from .native_turn_observation import RootCompletedNativeTurn
        from .root_memory_capture_consent import RootMemoryCaptureConsent, RootMemoryCaptureConsentRegistry

        turn_registry = self.native_turn_observation_registry
        consent_registry = self.memory_capture_consent_registry
        if (type(record) is not RootCompletedNativeTurn
                or type(enrollment) is not MemoryServiceEnrollment
                or type(consent_registry) is not RootMemoryCaptureConsentRegistry
                or turn_registry is None
                or type(owner_generation) is not int
                or owner_generation < 1
                or not isinstance(transcript_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", transcript_sha256)
                or transcript_sha256 != record.transcript_sha256
                or not isinstance(background_consent_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", background_consent_handle)):
            raise AuthorityDenied("memory.turn", "completed-turn capture request is malformed")
        resolve_turn = getattr(turn_registry, "resolve_completed_turn", None)
        if (not callable(resolve_turn)
                or resolve_turn(record.receipt_handle) is not record
                or record.expires_monotonic <= self.monotonic()
                or self.service_generation_digest is None
                or record.service_generation_digest != self.service_generation_digest
                or record.profile_id != enrollment.profile_id
                or enrollment.principal_id == ""
                or enrollment.service_enrollment_id == ""
                or enrollment.memory_owner_generation != owner_generation
                or record.process_generation != self.profile_generations.get(record.profile_id)):
            raise AuthorityDenied("memory.turn", "completed turn or selected memory generation is stale")

        matching_bindings = [binding for binding in self.bindings_by_uid.values()
                             if binding.profile_id == enrollment.profile_id]
        if (len(matching_bindings) != 1
                or matching_bindings[0].principal_id != enrollment.principal_id
                or matching_bindings[0].namespace_id != enrollment.namespace_identity):
            raise AuthorityDenied("memory.turn", "selected memory profile has no exact active principal")
        binding = matching_bindings[0]
        if (self.memory_owner_state is None
                or self.memory_owner_state(enrollment.profile_id)
                != (enrollment.provider, owner_generation)):
            raise AuthorityDenied("memory.turn", "selected memory owner epoch is no longer active")

        source_receipts = self._resolve_completed_turn_source_closure(record, binding)
        selected_resolver = getattr(consent_registry, "resolve_selected_memory_binding", None)
        resolve_consent = getattr(consent_registry, "resolve_capture_consent", None)
        if not callable(selected_resolver) or not callable(resolve_consent):
            raise AuthorityDenied("memory.consent", "root capture opt-in resolver is unavailable")
        selected_memory_binding = selected_resolver(enrollment.service_enrollment_id)
        if selected_memory_binding is not enrollment:
            raise AuthorityDenied("memory.consent", "capture opt-in selected another memory enrollment")
        capture_consent = resolve_consent(
            background_consent_handle,
            completed_turn_receipt_handle=record.receipt_handle,
            selected_memory_binding=selected_memory_binding,
        )
        memory_consent_claims = getattr(capture_consent, "claims", None)
        if (type(capture_consent) is not RootMemoryCaptureConsent
                or capture_consent.state != "enabled"
                or capture_consent.profile_id != enrollment.profile_id
                or capture_consent.principal_id != enrollment.principal_id
                or capture_consent.namespace_id != enrollment.namespace_identity
                or capture_consent.service_enrollment_id != enrollment.service_enrollment_id
                or capture_consent.service_generation != enrollment.service_generation
                or capture_consent.memory_owner_generation != owner_generation
                or capture_consent.provider != enrollment.provider
                or not capture_consent.route_ids
                or not capture_consent.private_recipient_ids
                or not set(capture_consent.route_ids).issubset(enrollment.fixed_route_map)
                or capture_consent.policy_revision != self._policy_revision()
                or capture_consent.revocation_epoch < 1
                or not callable(memory_consent_claims)):
            raise AuthorityDenied("memory.consent", "current capture opt-in does not match selected memory")
        self._verify_signature(
            {"domain": "root-memory-capture-consent-v1", **memory_consent_claims()},
            capture_consent.signature,
        )

        if not source_receipts or any(
                receipt.native_process_identity != source_receipts[0].native_process_identity
                for receipt in source_receipts):
            raise AuthorityDenied("memory.turn", "turn source closure has no single verified native identity")
        if len(source_receipts) > 64:
            raise AuthorityDenied("memory.turn", "verified turn closure exceeds the context receipt bound")
        lease = min(30.0, record.expires_monotonic - self.monotonic())
        if lease <= 0:
            raise AuthorityDenied("memory.turn", "completed-turn capture lease expired")
        context_wire = self._issue_context(binding.uid, {
            "purpose": "memory-capture",
            "intent": f"memory-capture:{enrollment.provider}:{record.turn_handle}",
            "trace_id": record.turn_handle,
            "lease_seconds": lease,
            "source_contexts": [],
            "source_receipts": [receipt.to_wire() for receipt in source_receipts],
            "final_payload_digest": transcript_sha256,
            "operation": "memory.capture",
        }, inherited_process_identity=source_receipts[0].native_process_identity)
        context = HostContext.from_wire(context_wire)
        if context.sensitivity not in {Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN}:
            raise AuthorityDenied("memory.turn", "memory capture context did not retain private sensitivity")
        job_consent = self.create_background_consent(
            context, provider_id=enrollment.provider, owner_generation=owner_generation,
            ttl_seconds=max(1, min(300, int(lease))),
            capture_consent=capture_consent,
            capture_consent_handle=background_consent_handle,
            completed_turn_receipt_handle=record.receipt_handle,
        )
        return context, job_consent

    def _resolve_completed_turn_source_closure(
        self, record: Any, binding: PrincipalBinding,
    ) -> tuple[SourceReceipt, ...]:
        """Resolve and authenticate every inner turn receipt plus ancestors."""
        handles = tuple(dict.fromkeys((
            record.input_receipt_handle, *record.request_receipt_handles,
            *record.response_receipt_handles, *record.tool_result_receipt_handles,
            *record.delegation_receipt_handles,
        )))
        if (not handles or len(handles) > 512
                or any(not isinstance(handle, str)
                       or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle)
                       for handle in handles)):
            raise AuthorityDenied("memory.turn", "completed turn has no bounded inner source closure")
        with self._lock:
            by_handle = self._source_receipt_handles
            direct = []
            for handle in handles:
                receipt = by_handle.get(handle)
                if receipt is None:
                    raise AuthorityDenied("memory.turn", "completed turn source receipt is unavailable")
                direct.append(receipt)
            by_id: dict[str, tuple[str, SourceReceipt]] = {}
            for handle, receipt in by_handle.items():
                if receipt.receipt_id in by_id:
                    raise AuthorityDenied("memory.turn", "root source receipt identifiers are ambiguous")
                by_id[receipt.receipt_id] = (handle, receipt)
            closure: dict[str, SourceReceipt] = {}
            pending = list(direct)
            while pending:
                receipt = pending.pop()
                if receipt.receipt_id in closure:
                    continue
                closure[receipt.receipt_id] = receipt
                if len(closure) > 512:
                    raise AuthorityDenied("memory.turn", "completed turn source closure exceeds its bound")
                for parent_id in receipt.parent_receipt_ids:
                    parent = by_id.get(parent_id)
                    if parent is None:
                        raise AuthorityDenied("memory.turn", "completed turn ancestor receipt is unavailable")
                    pending.append(parent[1])
        expected_digest = canonical_digest(sorted(closure))
        if expected_digest != record.parent_closure_digest:
            raise AuthorityDenied("memory.turn", "completed turn receipt closure digest changed")
        result = tuple(closure[key] for key in sorted(closure))
        for receipt in result:
            self._verify_source_receipt(receipt, binding)
            if (receipt.profile_id != record.profile_id
                    or receipt.process_generation != record.process_generation
                    or receipt.sensitivity not in {Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN}):
                raise AuthorityDenied("memory.turn", "completed turn receipt is bound to another profile or generation")
        return result

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

    def attach_selected_application_router(self, router: Any) -> None:
        """Attach the concrete root-selected application router once."""
        from .application_runtime import RootSelectedApplicationRuntimeRouter

        if (self.selected_application_router is not None
                or type(router) is not RootSelectedApplicationRuntimeRouter
                or router.service is not self
                or not callable(getattr(router, "dispatch", None))):
            raise AuthorityDenied("application.dispatch", "root selected application router is invalid")
        self.selected_application_router = router

    def dispatch_selected_application(
        self, invocation_context_handle: str, application_id: str,
        canonical_arguments: bytes, *, peer_uid: int, peer_pid: int,
        peer_pidfd: int | None, cancelled: Callable[[], bool],
    ) -> Any:
        """Dispatch one invocation through the attached typed root router.

        This in-process entrypoint carries kernel-authenticated peer identity
        from its caller. The router resolves the selected application/action
        and source closure; these arguments do not define a backend or target.
        """
        from .application_runtime import RootApplicationRunReceipt

        router = self.selected_application_router
        if (router is None or not isinstance(invocation_context_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", invocation_context_handle)
                or not isinstance(application_id, str) or not application_id
                or len(application_id) > 256
                or not isinstance(canonical_arguments, bytes)
                or not 1 <= len(canonical_arguments) <= 1_048_576
                or type(peer_uid) is not int or peer_uid <= 0
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or not callable(cancelled) or cancelled()):
            raise AuthorityDenied("application.dispatch", "selected application invocation is unavailable")
        try:
            receipt = router.dispatch(
                invocation_context_handle, application_id, canonical_arguments,
                peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                cancelled=cancelled,
            )
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("application.dispatch", "selected application invocation failed") from None
        if type(receipt) is not RootApplicationRunReceipt or cancelled():
            raise AuthorityDenied("application.dispatch", "application receipt is not root retained")
        return receipt

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

    def attach_channel_peer_delivery_registry(self, registry: Any) -> None:
        """Attach the root-selected, PIDFD-bound channel peer/event registry."""
        from .channel_peer_delivery import RootChannelPeerDeliveryRegistry

        if (self.channel_peer_delivery_registry is not None
                or type(registry) is not RootChannelPeerDeliveryRegistry
                or registry.service is not self
                or not callable(getattr(registry, "prove_retained_event_for_peer", None))
                or not callable(getattr(registry, "resolve_retained_channel_proof", None))
                or not callable(getattr(registry, "publish_issued_delivery", None))
                or not callable(getattr(registry, "validate_retained_channel_proof", None))):
            raise AuthorityDenied("channel.attach", "root channel peer delivery registry is invalid")
        self.channel_peer_delivery_registry = registry

    def attach_native_channel_context_store(self, store: Any) -> None:
        """Attach the exact one-use native channel context delivery store."""
        from .native_channel_context import RootNativeChannelContextStore

        if (self.native_channel_context_store is not None
                or type(store) is not RootNativeChannelContextStore
                or store.service is not self
                or not callable(getattr(store, "register_channel_context", None))
                or not callable(getattr(store, "verify_registered_channel_context", None))
                or not callable(getattr(store, "rollback_channel_context", None))):
            raise AuthorityDenied("channel.context", "root native channel context store is invalid")
        self.native_channel_context_store = store

    def issue_root_channel_event_delivery(
        self, event_handle: Any, channel_ingress_id: str,
        verified_native_peer_binding: Any,
    ) -> Any:
        """Create a source- and peer-bound one-use delivery for one retained event.

        This is root-internal only.  It re-resolves the exact event and native
        peer proof, signs a source child without changing its historical
        producer identity, and publishes only after both owner registries have
        retained the source and context bindings.
        """
        from .channel_peer_delivery import (
            RootChannelInputDelivery, RootRetainedChannelDeliveryProof,
            VerifiedNativeChannelPeerBinding,
        )
        from .resource_source_controllers import RootResourceEventHandle
        from .source_observers import SourceReceiptHandle

        channel_registry = self.channel_peer_delivery_registry
        source_registry = self.source_observer_registry
        context_store = self.native_channel_context_store
        if (channel_registry is None or source_registry is None or context_store is None
                or type(event_handle) is not RootResourceEventHandle
                or type(verified_native_peer_binding) is not VerifiedNativeChannelPeerBinding
                or not isinstance(channel_ingress_id, str)
                or channel_ingress_id != verified_native_peer_binding.channel_ingress_id
                or verified_native_peer_binding.expires_monotonic <= self.monotonic()):
            raise AuthorityDenied("channel.delivery", "root channel event or selected native peer is unavailable")
        proof = None
        source_token = None
        context_token = None
        source_handle = None
        receipt = None
        delivery = None
        try:
            proof = channel_registry.prove_retained_event_for_peer(
                event_handle, verified_native_peer_binding)
            if (type(proof) is not RootRetainedChannelDeliveryProof
                    or channel_registry.validate_retained_channel_proof(
                        proof, event_handle=event_handle,
                        native_binding=verified_native_peer_binding) is not True):
                raise AuthorityDenied("channel.proof", "retained event and native peer are not current")
            retained_event, native_binding = channel_registry.resolve_retained_channel_proof(proof)
            if retained_event is not event_handle or native_binding is not verified_native_peer_binding:
                raise AuthorityDenied("channel.proof", "retained event proof changed its selected peer")
            resource_registry = channel_registry.resource_registry
            record = resource_registry.resolve_retained_event(event_handle)
            if (record.handle is not event_handle or not isinstance(record.payload, bytes)
                    or canonical_digest(record.payload) != event_handle.payload_sha256
                    or canonical_digest(record.payload) != proof.event_payload_sha256
                    or len(record.payload) != proof.event_payload_size_bytes):
                raise AuthorityDenied("channel.event", "retained event payload no longer matches its proof")
            parents = tuple(record.parent_receipts)
            parent_ids = tuple(sorted(item.receipt_id for item in parents))
            closure_digest = canonical_digest(sorted(
                (item.receipt_id, canonical_digest(item.claims())) for item in parents))
            if (not parents or len(parents) != len(parent_ids)
                    or parent_ids != tuple(event_handle.source_receipt_ids)
                    or closure_digest != event_handle.parent_closure_digest
                    or tuple(record.parent_context.source_receipts) != parents):
                raise AuthorityDenied("channel.lineage", "retained event source closure is incomplete")
            binding = self._binding(native_binding.peer_uid)
            if (binding.profile_id != native_binding.profile_id
                    or binding.principal_id != native_binding.principal_id
                    or binding.namespace_id != native_binding.namespace_id
                    or self.profile_generations.get(binding.profile_id) != native_binding.generation
                    or any((item.uid, item.profile_id, item.principal_id, item.namespace_id,
                            item.process_generation) !=
                           (binding.uid, binding.profile_id, binding.principal_id,
                            binding.namespace_id, native_binding.generation)
                           for item in parents)):
                raise AuthorityDenied("channel.identity", "event ancestry and selected peer differ")
            self._verify_context_signature(record.parent_context)
            self._assert_current_context(record.parent_context, binding, binding.uid)
            for parent in parents:
                self._verify_source_receipt(parent, binding)
            now = self.monotonic()
            expiry = min(proof.expires_monotonic, native_binding.expires_monotonic,
                         event_handle.expires_monotonic, now + 30.0)
            if not now < expiry:
                raise AuthorityDenied("channel.expired", "event and peer leases do not overlap")
            observer = source_registry.observers.get(event_handle.source_observer_enrollment_id)
            if observer is None or observer.source_kind != "native-input":
                raise AuthorityDenied("channel.lineage", "retained event source observer is unavailable")
            source_leaf = [item for item in parents
                           if item.source_kind == "native-input"
                           and item.payload_digest == event_handle.payload_sha256
                           and item.origin_id == f"{observer.origin_id}:{event_handle.event_id}"]
            if len(source_leaf) != 1:
                raise AuthorityDenied("channel.lineage", "event source closure has no unique input leaf")
            parent_ceiling = frozenset.intersection(*(frozenset(item.recipient_ceiling) for item in parents))
            generation = self.profile_generations[binding.profile_id]
            enrollment_id = canonical_digest({
                "uid": binding.uid, "principal_id": binding.principal_id,
                "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
                "generation": generation, "authority_epoch": self.authority_epoch,
            })
            from .types import Sensitivity
            receipt = SourceReceipt(
                receipt_id=secrets.token_urlsafe(24),
                issuer_id="host-authority:root-channel-event-v129",
                source_kind="native-input", principal_id=binding.principal_id,
                profile_id=binding.profile_id, namespace_id=binding.namespace_id,
                uid=binding.uid,
                origin_id=f"{source_leaf[0].origin_id}:channel:{channel_ingress_id}",
                process_generation=generation, payload_digest=canonical_digest(record.payload),
                sensitivity=max((Sensitivity.PRIVATE, *(item.sensitivity for item in parents)),
                                key=lambda value: list(Sensitivity).index(value)),
                parent_lineage_hash=event_handle.parent_closure_digest,
                policy_revision=self._policy_revision(), recipient_ceiling=parent_ceiling,
                issued_at_monotonic=now, monotonic_expires_at=expiry, signature="pending",
                enrollment_id=enrollment_id,
                native_process_identity=source_leaf[0].native_process_identity,
                parent_receipt_ids=parent_ids, nonce=secrets.token_urlsafe(24),
            )
            receipt = replace(receipt, signature=self._sign({
                "domain": "root-channel-event-source-v129", **receipt.claims()}))
            source_handle = SourceReceiptHandle(secrets.token_urlsafe(32))
            with self._lock:
                if len(self._source_receipt_handles) >= 100_000 or str(source_handle) in self._source_receipt_handles:
                    raise AuthorityDenied("source.capacity", "root source receipt store is unavailable")
                self._source_receipt_handles[str(source_handle)] = receipt
            source_context = self._issue_root_channel_context(
                binding, native_binding, parents, receipt, record.payload, expiry)
            context_token = context_store.register_channel_context(
                proof=proof, native_binding=native_binding,
                source_receipt_handle=str(source_handle), source_context=source_context,
                event_payload_sha256=proof.event_payload_sha256,
                event_payload_size_bytes=proof.event_payload_size_bytes,
                expires_monotonic=expiry,
            )
            source_token = source_registry.register_root_channel_event_delivery(
                proof, source_handle, receipt, source_context, record.payload, expiry,
                context_token.producer_context_delivery_handle)
            if (str(source_token.source_receipt_handle) != str(source_handle)
                    or source_token.producer_context_delivery_handle
                    != context_token.producer_context_delivery_handle):
                raise AuthorityDenied("channel.registration", "source and context registrations differ")
            sequence = channel_registry.sequence_for_retained_channel_proof(proof)
            delivery = RootChannelInputDelivery(
                secrets.token_urlsafe(32), event_handle.handle,
                native_binding.binding_handle, str(source_handle),
                context_token.producer_context_delivery_handle,
                proof.event_payload_sha256, sequence, self.monotonic(), expiry,
                self._root_channel_delivery_token,
            )
            with self._lock:
                if len(self._root_channel_input_deliveries) >= 100_000:
                    raise AuthorityDenied("channel.capacity", "root channel delivery ledger is full")
                key = id(delivery)
                self._root_channel_input_deliveries[key] = delivery
                self._root_channel_source_registrations[key] = source_token
                self._root_channel_context_registrations[key] = context_token
            source_registry.commit_root_channel_event_delivery(source_token)
            channel_registry.publish_issued_delivery(proof, delivery)
            return delivery
        except AuthorityDenied:
            self._rollback_root_channel_delivery(
                proof, delivery, source_token, context_token, source_handle)
            raise
        except Exception:
            self._rollback_root_channel_delivery(
                proof, delivery, source_token, context_token, source_handle)
            raise AuthorityDenied("channel.delivery", "root channel source delivery could not be issued") from None

    def _issue_root_channel_context(
        self, binding: PrincipalBinding, native_binding: Any,
        parent_receipts: tuple[SourceReceipt, ...], receipt: SourceReceipt,
        event_payload: bytes, expires_monotonic: float,
    ) -> HostContext:
        """Sign a channel context while preserving historical producer IDs."""
        if (not parent_receipts or not isinstance(event_payload, bytes)
                or canonical_digest(event_payload) != receipt.payload_digest
                or receipt.native_process_identity == self._native_process_identity(
                    native_binding.peer_pid, native_binding.peer_uid)):
            raise AuthorityDenied("channel.context", "channel source/recipient identities are not distinct")
        peer_identity = self._native_process_identity(native_binding.peer_pid, native_binding.peer_uid)
        all_receipts = (*parent_receipts, receipt)
        if (len(all_receipts) > 64 or len({item.receipt_id for item in all_receipts}) != len(all_receipts)
                or any(not set(item.parent_receipt_ids).issubset(
                    {parent.receipt_id for parent in all_receipts}) for item in all_receipts)):
            raise AuthorityDenied("channel.context", "channel context source closure is invalid")
        purpose, intent = "resource-channel-input", f"resource-channel:{receipt.origin_id}"
        sensitivity, base_lineage = self.policy.classify(
            purpose=purpose, intent=intent, source_contexts=(), binding=binding)
        order = (Sensitivity.PUBLIC, Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN)
        sensitivity = max((sensitivity, *(item.sensitivity for item in all_receipts)), key=order.index)
        lineage = canonical_digest({
            "base": base_lineage,
            "receipts": sorted((item.receipt_id, canonical_digest(item.claims())) for item in all_receipts),
            "parents": sorted(item.parent_lineage_hash for item in all_receipts),
        })
        now = self.monotonic()
        generation = self.profile_generations[binding.profile_id]
        enrollment_id = canonical_digest({
            "uid": binding.uid, "principal_id": binding.principal_id,
            "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
            "generation": generation, "authority_epoch": self.authority_epoch,
        })
        context = HostContext(
            principal_id=binding.principal_id, profile_id=binding.profile_id,
            namespace_id=binding.namespace_id, uid=binding.uid, purpose=purpose,
            intent_id=canonical_digest({"purpose": purpose, "intent": intent}),
            trace_id=secrets.token_urlsafe(24), sensitivity=sensitivity,
            lineage_hash=lineage, policy_revision=self._policy_revision(),
            capabilities=binding.capabilities, issued_at_monotonic=now,
            monotonic_expires_at=min(expires_monotonic, now + MAX_CONTEXT_LEASE),
            nonce=secrets.token_urlsafe(24), grant_id=secrets.token_urlsafe(24),
            signature="pending", source_receipts=all_receipts,
            final_payload_digest=canonical_digest(event_payload),
            enrollment_id=enrollment_id, generation=generation,
            operation="native.request.dispatch", native_process_identity=peer_identity,
        )
        return replace(context, signature=self._sign({
            "domain": "root-channel-event-context-v129", **context.claims()}))

    def validate_root_channel_input_delivery(self, proof: Any, delivery: Any) -> bool:
        """Check exact service receipt and both owner-held registrations."""
        from .channel_peer_delivery import RootChannelInputDelivery

        if type(delivery) is not RootChannelInputDelivery:
            return False
        with self._lock:
            retained = self._root_channel_input_deliveries.get(id(delivery))
            source_token = self._root_channel_source_registrations.get(id(delivery))
            context_token = self._root_channel_context_registrations.get(id(delivery))
        if (retained is not delivery or delivery._issuer_token is not self._root_channel_delivery_token
                or source_token is None or context_token is None
                or not self.channel_peer_delivery_registry.validate_retained_channel_proof(proof)
                or proof.event_handle != delivery.event_handle
                or proof.native_binding_handle != delivery.native_binding_handle
                or proof.event_payload_sha256 != delivery.payload_sha256
                or delivery.expires_monotonic <= self.monotonic()):
            return False
        try:
            _event, native_binding = self.channel_peer_delivery_registry.resolve_retained_channel_proof(proof)
            peer_fd = native_binding.duplicate_peer_pidfd()
            try:
                source = self.source_observer_registry.resolve_root_channel_source_delivery(
                    delivery.source_receipt_handle, peer_uid=native_binding.peer_uid,
                    peer_pid=native_binding.peer_pid, peer_pidfd=peer_fd, require_pending=True)
                context_ok = self.native_channel_context_store.verify_registered_channel_context(
                    delivery.producer_context_delivery_handle, proof=proof,
                    native_binding=native_binding, source_receipt_handle=delivery.source_receipt_handle,
                    peer_uid=native_binding.peer_uid, peer_pid=native_binding.peer_pid,
                    peer_pidfd=peer_fd)
            finally:
                os.close(peer_fd)
            return bool(str(source) == delivery.source_receipt_handle and context_ok)
        except Exception:
            return False

    def revoke_root_channel_input_delivery(self, channel_delivery: Any) -> bool:
        """Revoke both owner-held registrations for one expired queued delivery."""
        delivery_handle = getattr(channel_delivery, "delivery_handle", None)
        with self._lock:
            key = next((item_key for item_key, item in self._root_channel_input_deliveries.items()
                        if item.delivery_handle == delivery_handle), None)
            if key is None:
                return False
            delivery = self._root_channel_input_deliveries.pop(key)
            source_token = self._root_channel_source_registrations.pop(key, None)
            context_token = self._root_channel_context_registrations.pop(key, None)
        revoked = False
        if source_token is not None:
            try:
                revoked = self.source_observer_registry.rollback_root_channel_event_delivery(source_token) or revoked
            except Exception:
                pass
        if context_token is not None:
            try:
                revoked = self.native_channel_context_store.rollback_channel_context(context_token) or revoked
            except Exception:
                pass
        with self._lock:
            self._source_receipt_handles.pop(delivery.source_receipt_handle, None)
        return revoked

    def _rollback_root_channel_delivery(self, proof: Any, delivery: Any,
                                       source_token: Any, context_token: Any,
                                       source_handle: Any) -> None:
        if delivery is not None:
            with self._lock:
                self._root_channel_input_deliveries.pop(id(delivery), None)
                self._root_channel_source_registrations.pop(id(delivery), None)
                self._root_channel_context_registrations.pop(id(delivery), None)
        if source_token is not None:
            try:
                self.source_observer_registry.rollback_root_channel_event_delivery(source_token)
            except Exception:
                pass
        if context_token is not None:
            try:
                self.native_channel_context_store.rollback_channel_context(context_token)
            except Exception:
                pass
        if source_handle is not None:
            with self._lock:
                self._source_receipt_handles.pop(str(source_handle), None)
        if proof is not None and self.channel_peer_delivery_registry is not None:
            try:
                self.channel_peer_delivery_registry.cancel_retained_channel_proof(proof)
            except Exception:
                pass

    def attach_private_input_consent_registry(self, registry: Any) -> None:
        """Attach the root-held private-egress consent registry exactly once."""
        from .root_private_input_consent import RootPrivateInputConsentRegistry

        if (self.private_input_consent_registry is not None
                or type(registry) is not RootPrivateInputConsentRegistry
                or registry.service is not self):
            raise AuthorityDenied("consent.attach", "root private-input consent registry is invalid")
        self.private_input_consent_registry = registry

    def attach_memory_capture_consent_registry(self, registry: Any) -> None:
        """Attach the separate persistent memory-capture opt-in registry."""
        from .root_memory_capture_consent import RootMemoryCaptureConsentRegistry

        if (self.memory_capture_consent_registry is not None
                or type(registry) is not RootMemoryCaptureConsentRegistry
                or registry.service is not self):
            raise AuthorityDenied("consent.attach", "root memory-capture consent registry is invalid")
        self.memory_capture_consent_registry = registry

    def root_display_receipt_signer(self) -> Any:
        """Return the in-process, domain-separated signer used by Xauthority receipts."""
        signer = _RootDisplayReceiptSigner(self)
        if not callable(getattr(signer, "sign", None)) or not callable(getattr(signer, "verify", None)):
            raise AuthorityDenied("display.receipt", "root display receipt signer is unavailable")
        return signer

    def attach_root_selected_startup_authority(self, authority: Any) -> None:
        """Attach the retained selected-startup admission resolver once."""
        from .selected_startup_authority import RootSelectedDisplayLaunchAuthority

        if (self.root_selected_startup_authority is not None
                or type(authority) is not RootSelectedDisplayLaunchAuthority
                or getattr(authority, "authority_service", None) is not self
                or not callable(getattr(authority, "resolve_current_admission", None))
                or not callable(getattr(authority, "resolve_selected_recipe_binding", None))
                or not callable(getattr(authority, "resolve_startup_controller_proof", None))
                or not callable(getattr(authority, "is_current", None))):
            raise AuthorityDenied("root-selected.attach", "startup authority binding is invalid")
        self.root_selected_startup_authority = authority

    def attach_root_selected_memory_authority(self, authority: Any) -> None:
        """Attach the retained selected-memory lifecycle resolver once."""
        from hermes_installer.memory.lifecycle_authority import RootMemoryServiceLifecycle

        if (self.root_selected_memory_authority is not None
                or type(authority) is not RootMemoryServiceLifecycle
                or getattr(authority, "authority_service", None) is not self
                or not callable(getattr(authority, "resolve_admission", None))
                or not callable(getattr(authority, "resolve_admission", None))):
            raise AuthorityDenied("root-selected.attach", "memory lifecycle authority binding is invalid")
        self.root_selected_memory_authority = authority

    def issue_root_selected_service_effect(
        self, admission: Any, selected_recipe_binding: Any, action: str,
        canonical_payload_bytes: bytes,
    ) -> RootSelectedServiceEffectGrant:
        """Mint one finite, root-local grant for an exact selected lifecycle action.

        This API is deliberately in-process only. Its admission and recipe must
        be retained typed objects from the startup or memory authority; no
        worker RPC accepts these records.
        """
        authority, current_admission, binding = self._resolve_root_selected_binding(
            admission, selected_recipe_binding, action,
        )
        if not isinstance(canonical_payload_bytes, bytes) or not 1 <= len(canonical_payload_bytes) <= 65_536:
            raise AuthorityDenied("root-selected.issue", "selected service payload is outside its bound")
        try:
            decoded = strict_json_loads(canonical_payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise AuthorityDenied("root-selected.issue", "selected service payload is not canonical JSON") from None
        if canonical_bytes(decoded) != canonical_payload_bytes:
            raise AuthorityDenied("root-selected.issue", "selected service payload is not canonical JSON")
        role = self._selected_binding_text(binding, "role")
        enrollment_id = self._selected_binding_text(binding, "service_enrollment_id")
        operation = self._selected_binding_text(binding, "operation")
        if action not in {"start", "status", "stop"} or operation != f"process.{action}":
            raise AuthorityDenied("root-selected.issue", "selected service action is not fixed")
        expected_payload = getattr(binding, "payload", None)
        if callable(expected_payload):
            expected_bytes = expected_payload()
        elif action == "start":
            expected_bytes = canonical_bytes({
                "schema": 1, "enrollment_id": enrollment_id,
                "generation": self._selected_binding_text(binding, "generation"),
                "operation_id": self._selected_binding_text(binding, "operation_id"),
                "parameters": {},
            })
        elif action == "status":
            process_id = getattr(binding, "process_id", None)
            if not isinstance(process_id, str) or not process_id:
                raise AuthorityDenied("root-selected.issue", "selected process control handle is unavailable")
            expected_bytes = canonical_bytes({"schema": 1, "process_id": process_id,
                                              "generation": self._selected_binding_text(binding, "generation")})
        else:
            process_id = getattr(binding, "process_id", None)
            reason = getattr(binding, "stop_reason", None)
            grace_seconds = getattr(binding, "stop_grace_seconds", None)
            if (not isinstance(process_id, str) or not process_id
                    or reason not in {"shutdown", "cancel", "rollback"}
                    or type(grace_seconds) is not int or grace_seconds != 5):
                raise AuthorityDenied("root-selected.issue", "selected stop recipe is unavailable")
            expected_bytes = canonical_bytes({
                "schema": 1, "process_id": process_id,
                "generation": self._selected_binding_text(binding, "generation"),
                "reason": reason, "grace_seconds": 5,
            })
        if not isinstance(expected_bytes, bytes) or expected_bytes != canonical_payload_bytes:
            raise AuthorityDenied("root-selected.issue", "payload does not match the retained operation recipe")
        capability = self._selected_binding_text(binding, "capability")
        target = self._selected_binding_text(binding, "target")
        rule = self.rules.get((capability, operation, target))
        recipient = getattr(binding, "recipient", None)
        if (rule is None or rule.operation != operation or rule.target != target
                or rule.recipient != recipient):
            raise AuthorityDenied("root-selected.issue", "selected operation has no exact protected rule")
        profile = getattr(binding, "service_profile", None)
        process_operation = getattr(binding, "process_operation", None)
        if profile is None or process_operation is None:
            raise AuthorityDenied("root-selected.issue", "selected managed operation is unavailable")
        controller = self._resolve_root_selected_controller(authority, current_admission, binding)
        try:
            now = self.monotonic()
            lease_deadlines = [now + MAX_EFFECT_LEASE]
            for candidate in (getattr(current_admission, "expires_monotonic", None),
                              getattr(controller, "expires_monotonic", None),
                              getattr(binding, "deadline_monotonic", None)):
                if isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
                    lease_deadlines.append(float(candidate))
            expiry = min(lease_deadlines)
            if expiry <= now:
                raise AuthorityDenied("root-selected.issue", "selected service admission has expired")
            sensitivity = getattr(binding, "sensitivity", getattr(current_admission, "sensitivity", Sensitivity.UNKNOWN))
            try:
                sensitivity = sensitivity if isinstance(sensitivity, Sensitivity) else Sensitivity(sensitivity)
            except ValueError:
                raise AuthorityDenied("root-selected.issue", "selected source sensitivity is invalid") from None
            fields = {
                "schema": 1, "context_id": secrets.token_urlsafe(24),
                "admission_handle": self._selected_binding_text(current_admission, "admission_handle"),
                "admission_kind": "memory" if current_admission is getattr(authority, "memory_admission", None) else
                    ("memory" if type(current_admission).__module__.startswith("hermes_installer.memory.") else "startup"),
                "controller_proof_sha256": self._selected_controller_digest(current_admission, binding, controller),
                "selected_principal_id": self._selected_binding_text(binding, "principal_id"),
                "selected_profile_id": self._selected_binding_text(binding, "profile_id"),
                "selected_generation": self._selected_binding_text(binding, "generation"),
                "selected_namespace_identity": self._selected_binding_text(binding, "namespace_identity"),
                "selected_subject_uid": self._selected_binding_int(binding, "subject_uid", minimum=1),
                "selected_subject_gid": self._selected_binding_int(binding, "subject_gid", minimum=0),
                "service_generation_digest": self._selected_binding_digest(current_admission, binding),
                "role": role, "action": action, "enrollment_id": enrollment_id,
                "operation_id": self._selected_binding_text(binding, "operation_id"),
                "operation": operation, "capability": capability, "target": target,
                "source_closure_sha256": self._selected_binding_text(binding, "source_closure_sha256"),
                "sensitivity": sensitivity,
                "recipient": getattr(binding, "recipient", None),
                "policy_revision": self._policy_revision(), "authority_epoch": self.authority_epoch,
                "issued_monotonic": now, "expires_monotonic": expiry,
                "nonce": secrets.token_hex(32),
            }
            context = RootSelectedServiceContext(**fields, signature=self._sign_root_selected(
                "root-selected-service-context-v1", fields,
            ))
            payload_sha = hashlib.sha256(canonical_payload_bytes).hexdigest()
            if not self.policy.allow_effect(context=context, rule=rule,
                                            request_digest=payload_sha, retry_index=0):
                raise AuthorityDenied("root-selected.issue", "current host policy denied selected service action")
            context_sha = hashlib.sha256(self._canonical_root_selected(context.to_wire())).hexdigest()
            nonce = secrets.token_hex(32)
            grant_fields = {
                "schema": 1, "grant_id": secrets.token_urlsafe(24),
                "context_sha256": context_sha, "admission_handle": context.admission_handle,
                "operation": operation, "capability": capability, "target": target,
                "request_sha256": payload_sha,
                "nonce": nonce, "issued_monotonic": now, "expires_monotonic": expiry,
            }
            grant = RootSelectedServiceEffectGrant(**grant_fields, signature=self._sign_root_selected(
                "root-selected-service-effect-v1", grant_fields,
            ))
            with self._lock:
                self._prune_root_selected_effects(now)
                if nonce in self._root_selected_nonce_states or len(self._root_selected_effects) >= 10_000:
                    raise AuthorityDenied("root-selected.issue", "selected service nonce registry is unavailable")
                self._root_selected_nonce_states[nonce] = ("pending", expiry)
                self._root_selected_service_effects[grant.grant_id] = {
                    "grant": grant, "context": context, "admission": current_admission,
                    "authority": authority, "binding": binding, "controller": controller,
                    "seal": self._root_selected_seal, "state": "pending",
                }
            return grant
        finally:
            close = getattr(controller, "close", None)
            if authority is self.root_selected_startup_authority and callable(close):
                close()

    def consume_root_selected_service_effect(
        self, grant: RootSelectedServiceEffectGrant, admission: Any,
        selected_profile: Any, canonical_payload_bytes: bytes,
    ) -> VerifiedRootSelectedServiceEffect:
        """Atomically spend a pending selected-service grant and seal its effect."""
        if type(grant) is not RootSelectedServiceEffectGrant:
            raise AuthorityDenied("root-selected.consume", "selected service grant has the wrong type")
        now = self.monotonic()
        self._verify_root_selected_signature("root-selected-service-effect-v1", grant.claims(), grant.signature)
        payload_digest = hashlib.sha256(canonical_payload_bytes).hexdigest() if isinstance(canonical_payload_bytes, bytes) else ""
        with self._lock:
            self._prune_root_selected_effects(now)
            entry = self._root_selected_service_effects.get(grant.grant_id)
            if (entry is None or entry["grant"] is not grant or entry["state"] != "pending"
                    or self._root_selected_nonce_states.get(grant.nonce) != ("pending", grant.expires_monotonic)
                    or grant.expires_monotonic <= now or grant.request_sha256 != payload_digest
                    or grant.admission_handle != getattr(admission, "admission_handle", None)):
                raise AuthorityDenied("root-selected.consume", "selected service grant is stale, mismatched or spent")
            authority, current_admission, binding = self._resolve_root_selected_binding(
                admission, entry["binding"], entry["context"].action,
            )
            if (authority is not entry["authority"] or current_admission is not entry["admission"]
                    or binding != entry["binding"] or selected_profile is not getattr(binding, "service_profile", None)
                    or grant.operation != entry["context"].operation
                    or grant.capability != entry["context"].capability
                    or grant.target != entry["context"].target
                    or hashlib.sha256(self._canonical_root_selected(entry["context"].to_wire())).hexdigest() != grant.context_sha256):
                raise AuthorityDenied("root-selected.consume", "selected service binding changed")
            self._verify_root_selected_signature(
                "root-selected-service-context-v1", entry["context"].claims(), entry["context"].signature,
            )
            rule = self.rules.get((entry["context"].capability, entry["context"].operation,
                                  entry["context"].target))
            if (rule is None or rule.recipient != entry["context"].recipient
                    or not self.policy.allow_effect(context=entry["context"], rule=rule,
                                                    request_digest=grant.request_sha256, retry_index=0)):
                raise AuthorityDenied("root-selected.consume", "current host policy denied selected service action")
            controller = self._resolve_root_selected_controller(authority, current_admission, binding)
            try:
                if not controller.is_current():
                    raise AuthorityDenied("root-selected.consume", "selected service controller is no longer live")
            finally:
                close = getattr(controller, "close", None)
                if callable(close):
                    close()
            self._root_selected_nonce_states[grant.nonce] = ("consumed", grant.expires_monotonic)
            entry["state"] = "consumed"
            controller_handle = self._selected_binding_text(entry["context"], "admission_handle")
            effect = VerifiedRootSelectedServiceEffect(
                admission_handle=controller_handle,
                admission_kind=entry["context"].admission_kind,
                role=entry["context"].role, action=entry["context"].action,
                profile_id=entry["context"].selected_profile_id,
                enrollment_id=entry["context"].enrollment_id,
                generation=entry["context"].selected_generation,
                selected_principal_id=entry["context"].selected_principal_id,
                selected_namespace_identity=entry["context"].selected_namespace_identity,
                selected_subject_uid=entry["context"].selected_subject_uid,
                selected_subject_gid=entry["context"].selected_subject_gid,
                operation=entry["context"].operation, capability=entry["context"].capability,
                target=entry["context"].target, request_sha256=grant.request_sha256,
                controller_proof_handle=self._root_selected_controller_handle(entry["admission"]),
                controller_proof_sha256=entry["context"].controller_proof_sha256,
                service_generation_digest=entry["context"].service_generation_digest,
                issued_monotonic=grant.issued_monotonic, expires_monotonic=grant.expires_monotonic,
                context_sha256=grant.context_sha256,
                operation_id=self._selected_binding_text(binding, "operation_id"),
                recipe_sha256=self._selected_binding_text(binding, "recipe_sha256"),
                source_closure_sha256=entry["context"].source_closure_sha256,
                service_profile=binding.service_profile, process_operation=binding.process_operation,
                _service=self, _nonce=grant.nonce,
                _seal=self._root_selected_seal,
            )
            entry["verified"] = effect
            return effect

    def _resolve_root_selected_binding(self, admission: Any, binding: Any,
                                       action: str) -> tuple[Any, Any, Any]:
        startup = self.root_selected_startup_authority
        memory = self.root_selected_memory_authority
        if startup is not None and type(admission).__module__ == "hermes_installer.authority.selected_startup_authority":
            authority = startup
            current = authority.resolve_current_admission(admission.admission_handle)
            stop_reason = getattr(binding, "stop_reason", "shutdown")
            if action == "stop" and stop_reason not in {"shutdown", "cancel", "rollback"}:
                raise AuthorityDenied("root-selected.binding", "selected stop reason is invalid")
            if action != "stop" and getattr(binding, "stop_reason", None) is not None:
                raise AuthorityDenied("root-selected.binding", "stop reason is only valid for stop")
            selected = authority.resolve_selected_recipe_binding(
                current, binding.role, action, _stop_reason=stop_reason,
            )
            expected = type(admission)
        elif memory is not None and type(admission).__module__ == "hermes_installer.memory.lifecycle_authority":
            authority = memory
            current = authority.resolve_admission(admission.admission_handle)
            reason = getattr(binding, "stop_reason", None)
            try:
                if action == "stop":
                    selected = current.action(action, now=self.monotonic(), reason=reason)
                else:
                    selected = current.action(action, now=self.monotonic())
            except (TypeError, ValueError):
                raise AuthorityDenied("root-selected.binding", "selected memory action resolver is unavailable") from None
            expected = type(admission)
        else:
            raise AuthorityDenied("root-selected.binding", "selected lifecycle admission is unavailable")
        if (type(admission) is not expected or current is not admission or selected != binding
                or getattr(selected, "service_profile", None) is not getattr(binding, "service_profile", None)
                or getattr(selected, "process_operation", None) != getattr(binding, "process_operation", None)
                or getattr(selected, "source_receipt_handles", None) != getattr(binding, "source_receipt_handles", None)
                or not callable(getattr(authority, "is_current", None)) and authority is startup
                or authority is startup and not authority.is_current(current)
                or action not in {"start", "status", "stop"}
                or getattr(binding, "action", None) != action):
            raise AuthorityDenied("root-selected.binding", "selected lifecycle admission or recipe is stale")
        if authority is memory:
            if not current.is_current(now=self.monotonic()):
                raise AuthorityDenied("root-selected.binding", "memory lifecycle admission is no longer current")
        return authority, current, binding

    def _resolve_root_selected_controller(self, authority: Any, admission: Any, binding: Any) -> Any:
        admission_handle = self._selected_binding_text(admission, "admission_handle")
        if authority is self.root_selected_startup_authority:
            handle = self._selected_binding_text(admission, "controller_proof_handle")
            proof = authority.resolve_startup_controller_proof(handle, admission_handle)
        else:
            proof = getattr(admission, "_controller_lease", None)
        if proof is None or not callable(getattr(proof, "is_current", None)) or not proof.is_current():
            raise AuthorityDenied("root-selected.controller", "selected service controller proof is stale")
        return proof

    @staticmethod
    def _root_selected_controller_handle(admission: Any) -> str:
        value = getattr(admission, "controller_proof_handle", None)
        if value is None:
            value = getattr(getattr(admission, "_controller_lease", None), "proof_handle", None)
        if not isinstance(value, str) or not value:
            raise AuthorityDenied("root-selected.controller", "controller proof handle is unavailable")
        return value

    def _selected_controller_digest(self, admission: Any, binding: Any, controller: Any) -> str:
        value = getattr(binding, "controller_proof_sha256", None) or getattr(admission, "controller_proof_sha256", None)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            value = canonical_digest({"pid": getattr(controller, "pid", None),
                                     "uid": getattr(controller, "uid", None),
                                     "start_ticks": getattr(controller, "start_ticks", None),
                                     "identity": getattr(controller, "kernel_identity", None)})
        return value

    def _selected_binding_digest(self, admission: Any, binding: Any) -> str:
        value = getattr(binding, "service_generation_digest", None) or getattr(admission, "service_generation_digest", None)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise AuthorityDenied("root-selected.binding", "selected service generation digest is invalid")
        if self.service_generation_digest is not None and value != self.service_generation_digest:
            raise AuthorityDenied("root-selected.binding", "selected service generation is stale")
        return value

    @staticmethod
    def _selected_binding_text(binding: Any, name: str) -> str:
        value = getattr(binding, name, None)
        if not isinstance(value, str) or not value or len(value) > 512:
            raise AuthorityDenied("root-selected.binding", f"selected binding {name} is invalid")
        return value

    @staticmethod
    def _selected_binding_int(binding: Any, name: str, *, minimum: int) -> int:
        value = getattr(binding, name, None)
        if type(value) is not int or value < minimum:
            raise AuthorityDenied("root-selected.binding", f"selected binding {name} is invalid")
        return value

    def _sign_root_selected(self, domain: str, claims: Mapping[str, Any]) -> str:
        envelope = {"domain": domain, "key_id": self.key_id, "claims": dict(claims)}
        encoded = self._canonical_root_selected(envelope)
        return hmac.new(self._key, encoded, hashlib.sha256).hexdigest()

    @staticmethod
    def _canonical_root_selected(value: Mapping[str, Any]) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _verify_root_selected_signature(self, domain: str, claims: Mapping[str, Any], signature: str) -> None:
        expected = self._sign_root_selected(domain, claims)
        if not hmac.compare_digest(expected, signature):
            raise AuthorityDenied("root-selected.signature", "selected service signature is invalid")

    def _prune_root_selected_effects(self, now: float) -> None:
        for grant_id, entry in tuple(self._root_selected_service_effects.items()):
            if entry["grant"].expires_monotonic <= now:
                self._root_selected_service_effects.pop(grant_id, None)
        for nonce, (_state, expires) in tuple(self._root_selected_nonce_states.items()):
            if expires <= now:
                self._root_selected_nonce_states.pop(nonce, None)

    def _is_current_root_selected_service_effect(self, effect: VerifiedRootSelectedServiceEffect,
                                                seal: object) -> bool:
        if seal is not self._root_selected_seal or effect._service is not self:
            return False
        with self._lock:
            entry = self._root_selected_service_effects.get(next((key for key, item in self._root_selected_service_effects.items()
                if item.get("verified") is effect), ""))
            if (entry is None or entry["state"] != "consumed"
                    or self._root_selected_nonce_states.get(effect._nonce)
                    != ("consumed", effect.expires_monotonic)
                    or effect.expires_monotonic <= self.monotonic()):
                return False
            try:
                authority, admission, binding = self._resolve_root_selected_binding(
                    entry["admission"], entry["binding"], effect.action,
                )
                controller = self._resolve_root_selected_controller(authority, admission, binding)
                try:
                    context = entry["context"]
                    rule = self.rules.get((effect.capability, effect.operation, effect.target))
                    return bool(
                        context.authority_epoch == self.authority_epoch
                        and context.policy_revision == self._policy_revision()
                        and context.service_generation_digest == self._selected_binding_digest(admission, binding)
                        and rule is not None and rule.recipient == context.recipient
                        and self.policy.allow_effect(
                            context=context, rule=rule, request_digest=effect.request_sha256,
                            retry_index=0,
                        )
                        and controller.is_current()
                    )
                finally:
                    close = getattr(controller, "close", None)
                    if authority is self.root_selected_startup_authority and callable(close):
                        close()
            except Exception:
                return False

    def _close_root_selected_service_effect(self, effect: VerifiedRootSelectedServiceEffect,
                                            seal: object) -> None:
        if seal is not self._root_selected_seal or effect._service is not self:
            return
        with self._lock:
            for grant_id, entry in tuple(self._root_selected_service_effects.items()):
                if entry.get("verified") is effect:
                    self._root_selected_service_effects.pop(grant_id, None)
                    return

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

    def attach_resource_task_authority(self, authority: Any) -> None:
        """Attach the service-bound RB-T08 signer/consumer exactly once."""
        from .resource_task_authority import RootResourceTaskAuthority

        if (self.resource_task_authority is not None
                or type(authority) is not RootResourceTaskAuthority
                or authority.service is not self
                or authority.jobs is not self.resource_job_authority):
            raise AuthorityDenied("resource.task_authority", "root resource task authority is invalid")
        self.resource_task_authority = authority

    def issue_root_resource_task_start(self, child_admission: Any, task_source: Any,
                                       task_admission: Any, selected_execution: Any, *,
                                       task_handle: Any, controller: Any) -> Any:
        authority = self.resource_task_authority
        if authority is None:
            raise AuthorityDenied("resource.task_start", "root resource task authority is unavailable")
        return authority.issue_root_resource_task_start(
            child_admission, task_source, task_admission, selected_execution,
            task_handle=task_handle, controller=controller,
        )

    def consume_root_resource_task_start(self, grant: Any, child_admission: Any,
                                         task_source: Any, task_admission: Any,
                                         canonical_selection_payload: bytes, *,
                                         task_handle: Any) -> Any:
        authority = self.resource_task_authority
        if authority is None:
            raise AuthorityDenied("resource.task_start", "root resource task authority is unavailable")
        return authority.consume_root_resource_task_start(
            grant, child_admission, task_source, task_admission,
            canonical_selection_payload, task_handle=task_handle,
        )

    def verify_consumed_resource_task_start(self, proof: Any, canonical_selection_payload: bytes, *,
                                            task_admission: Any, selected_profile: Any) -> bool:
        authority = self.resource_task_authority
        return bool(authority is not None and authority.verify_consumed_start(
            proof, canonical_selection_payload, task_admission=task_admission,
            selected_profile=selected_profile,
        ))

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

    def perform_root_admitted_resource_process_start(
        self, admission: Any, task: Any, source: Any, controller: Any, selection: Any,
        *, exact_stdin: bytes, timeout: float, cancelled: Callable[[], bool],
    ) -> Any:
        """Start a root-controlled admitted task with a distinct sealed proof.

        Root controller identity is verified as provenance by the job and task
        authorities. It is never passed as the selected child process's peer.
        """
        from .resource_task_authority import RootResourceTaskAuthority
        from hermes_installer.registry.resource_jobs import (
            RootAdmittedTask, RootAdmittedTaskSource, RootResourceJobAdmissionHandle,
            RootTaskController,
        )
        from hermes_installer.registry.resource_backends import SelectedResourceProfileTask
        from hermes_installer.managed_process_custodian import ManagedTaskHandle

        jobs, authority, manager = (self.resource_job_authority,
                                    self.resource_task_authority,
                                    self.process_effect_handler)
        if (jobs is None or type(authority) is not RootResourceTaskAuthority
                or authority.service is not self or authority.jobs is not jobs
                or manager is None
                or not isinstance(admission, RootResourceJobAdmissionHandle)
                or not isinstance(task, RootAdmittedTask)
                or not isinstance(source, RootAdmittedTaskSource)
                or not isinstance(controller, RootTaskController)
                or controller.controller_kind not in {"root-scheduler", "root-webhook", "root-channel"}
                or not isinstance(selection, SelectedResourceProfileTask)
                or not isinstance(exact_stdin, bytes) or not 1 <= len(exact_stdin) <= 262_144
                or not callable(cancelled) or cancelled()
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or timeout <= 0):
            raise AuthorityDenied("resource.task_start", "root-controlled selected task is unavailable")
        if (jobs.verify_admitted_root_task_controller(admission, task, source, controller) is not True
                or hashlib.sha256(exact_stdin).hexdigest() != task.stdin_sha256
                or len(exact_stdin) != task.stdin_size_bytes
                or task.node_id != admission.node_id or source.parent_closure_digest != task.parent_closure_digest
                or self.monotonic() >= min(admission.expires_monotonic, task.deadline_monotonic,
                                           source.expires_monotonic, controller.expires_monotonic)):
            raise AuthorityDenied("resource.task_start", "root task provenance, input or lease changed")
        child = jobs.resolve_task_child_admission(admission, admission.node_id)
        profile = getattr(manager, "profiles", {}).get(selection.profile_id)
        if profile is None:
            raise AuthorityDenied("resource.task_start", "selected task process profile is unavailable")
        payload = authority.selection_payload(admission, task, selection, profile)
        grant = self.issue_root_resource_task_start(
            child, source, task, selection, task_handle=admission, controller=controller,
        )
        proof = self.consume_root_resource_task_start(
            grant, child, source, task, payload, task_handle=admission,
        )
        if (not self.verify_consumed_resource_task_start(
                proof, payload, task_admission=task, selected_profile=profile)
                or cancelled()):
            raise AuthorityDenied("resource.task_start", "sealed root task proof is no longer current")
        start = getattr(manager, "start_selected_resource_task", None)
        coordinator = getattr(manager, "task_input_coordinator", None)
        if not callable(start) or coordinator is None:
            raise AuthorityDenied("resource.task_start", "root selected task custodian is unavailable")
        result = start(
            profile, proof, payload, task_admission=task,
            admission_handle=admission, node_id=task.node_id, admitted_source=source,
            exact_stdin=exact_stdin,
            expected_stdin_sha256=task.stdin_sha256,
            timeout=min(float(timeout), max(0.001, proof.authorization.expires_monotonic - self.monotonic())),
            cancelled=cancelled, initial_input_coordinator=coordinator,
        )
        if not isinstance(result, ManagedTaskHandle) or cancelled():
            raise AuthorityDenied("resource.task_start", "root selected task did not start cleanly")
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
        """Issue a source receipt for ordinary observed sources only.

        Selected native input has a separate consent-bearing issuer below;
        permitting it through this generic path would discard the recipient
        ceiling derived from its selected profile choice.
        """
        if getattr(observation, "selected_execution", None) is not None:
            raise AuthorityDenied("source.native_input", "selected input requires private-consent issuance")
        return self._issue_observed_source(observation, selected_input_consent=None)

    def issue_selected_input_source(self, observation: Any) -> Any:
        """Mint selected native-input provenance with its private-route ceiling.

        Consent is resolved from the root-derived selection handle and the
        exact retained input proof. The generic source issuer cannot mint this
        receipt, and no worker chooses recipients or increases the budget.
        """
        from .source_observers import VerifiedSourceObservation

        registry = self.private_input_consent_registry
        selected = getattr(observation, "selected_execution", None)
        consent_handle = getattr(observation, "private_consent_selection_handle", None)
        if (type(observation) is not VerifiedSourceObservation or selected is None
                or observation.source_kind != "native-input"
                or consent_handle is not None
                and (not isinstance(consent_handle, str) or registry is None)):
            raise AuthorityDenied("source.native_input", "selected input binding is unavailable")
        if consent_handle is None:
            if self.source_observer_registry is None:
                raise AuthorityDenied("source.native_input", "root selected-input registry is unavailable")
            return self._issue_observed_source(
                observation, selected_input_consent=None, selected_input=True)
        resolve = getattr(registry, "resolve_for_selected_input", None)
        if not callable(resolve):
            raise AuthorityDenied("source.native_input", "root private-input consent resolver is unavailable")
        consent = resolve(consent_handle, observed_input_proof=observation,
                          selected_input_binding=selected)
        from .root_private_input_consent import RootPrivateInputConsent
        if (type(consent) is not RootPrivateInputConsent
                or consent.selection_handle != consent_handle
                or consent.input_observation_handle != observation.proof_nonce
                or consent.retained_input_selection_handle != selected.selection_handle
                or consent.profile_id != observation.profile_id
                or consent.principal_id != observation.principal_id
                or consent.namespace_id != observation.namespace_id
                or consent.profile_generation != observation.generation
                or consent.service_generation_digest != self.service_generation_digest
                or not set(consent.provider_route_ids).issubset(observation.private_provider_route_ids)
                or not consent.private_recipient_ids
                or consent.additional_metered_budget_usd != 0.0
                or consent.policy_revision != self._policy_revision()
                or consent.expires_monotonic <= self.monotonic()
                or consent.issued_monotonic > self.monotonic()):
            raise AuthorityDenied("source.native_input", "current private-input consent does not match selected input")
        self._verify_signature({"domain": "root-private-input-consent-v1", **consent.claims()},
                               consent.signature)
        handle = self._issue_observed_source(
            observation, selected_input_consent=consent, selected_input=True)
        try:
            from .source_observers import SourceReceiptHandle
            if type(handle) is not SourceReceiptHandle:
                raise AuthorityDenied("source.native_input", "private input issuer returned an invalid receipt handle")
            retain = getattr(self.source_observer_registry, "retain_selected_input_consent", None)
            if not callable(retain):
                raise AuthorityDenied("source.native_input", "selected-input consent retention is unavailable")
            retain(observation, selected, handle, consent)
        except AuthorityDenied:
            with self._lock:
                self._source_receipt_handles.pop(str(handle), None)
            raise
        except Exception:
            with self._lock:
                self._source_receipt_handles.pop(str(handle), None)
            raise AuthorityDenied("source.native_input", "selected-input consent association failed") from None
        return handle

    def issue_public_input_source(self, proof: Any, selected_execution: Any) -> Any:
        """Mint one PUBLIC native-input leaf for a separately selected web permission.

        Public classification comes only from the source registry's distinct
        sealed proof and its retained PUBLIC-only parent closure. The private
        input-consent path is never consulted or widened here.
        """
        from .source_observers import (
            RootPublicNativeInputObservation, RootSelectedNativeExecution,
            SourceReceiptHandle, SourceObserverRegistry,
        )
        from .root_public_input_permission import (
            RootPublicInputPermission, RootPublicInputPermissionRegistry,
        )
        try:
            from .public_web_selection import RootTTYPublicInputDisclosure
        except ImportError:
            raise AuthorityDenied(
                "source.public_input", "root TTY public-input disclosure support is unavailable") from None

        source_registry = self.source_observer_registry
        permission_registry = self.public_input_permission_registry
        verify_proof = getattr(source_registry, "verify_current_public_input_observation", None)
        if (type(proof) is not RootPublicNativeInputObservation
                or type(selected_execution) is not RootSelectedNativeExecution
                or type(source_registry) is not SourceObserverRegistry
                or type(permission_registry) is not RootPublicInputPermissionRegistry
                or not callable(verify_proof)
                or verify_proof(proof, selected_execution) is not True
                or proof.expires_monotonic <= self.monotonic()
                or proof.source_classification is not Sensitivity.PUBLIC
                or selected_execution.public_input_permission_selection_handle
                   != proof.public_permission_selection_handle
                or selected_execution.private_consent_selection_handle is not None):
            raise AuthorityDenied("source.public_input", "current root public-input proof is unavailable")

        # This exact registry validates the persistent root TTY choice, current
        # protected scope rows, and pending proof before it consumes that proof.
        permission = permission_registry.resolve_for_selected_input(proof, selected_execution)
        self._verify_public_input_permission(permission)
        if (permission.retained_input_selection_handle != selected_execution.selection_handle
                or permission.input_observation_handle != proof.observation_handle
                or permission.input_sha256 != proof.input_sha256
                or permission.profile_id != proof.profile_id
                or permission.profile_generation != proof.profile_generation
                or permission.principal_id != proof.principal_id
                or permission.namespace_id != proof.namespace_id
                or permission.service_generation_digest != self.service_generation_digest
                or permission.allowed_operations != ("plugin.web.read",)
                or not permission.public_recipient_ids
                or permission.additional_metered_budget_usd != 0.0):
            raise AuthorityDenied("source.public_input", "public permission does not bind this exact input")

        source_handle = None
        try:
            material = source_registry.resolve_consumed_public_input_source_material(proof)
            verify_disclosure = getattr(
                source_registry, "verify_current_public_input_observation", None)
            if (material.observation is not proof
                    or material.selected_execution is not selected_execution
                    or material.consumed is not True
                    or type(material.disclosure) is not RootTTYPublicInputDisclosure
                    or material.disclosure.disclosure_observation_handle
                       != proof.disclosure_observation_handle
                    or material.disclosure.input_sha256 != proof.input_sha256
                    or material.disclosure.input_size_bytes != proof.input_size_bytes
                    or material.disclosure.public_permission_selection_handle
                       != proof.public_permission_selection_handle
                    or material.disclosure.selected_execution_handle
                       != selected_execution.selection_handle
                    or not callable(verify_disclosure)
                    or verify_disclosure(proof, selected_execution) is not True
                    or material.source_proof.proof_nonce != proof.source_observation_handle
                    or material.source_proof.selected_execution is not selected_execution
                    or not isinstance(material.payload_bytes, bytes)
                    or hashlib.sha256(material.payload_bytes).hexdigest() != proof.input_sha256
                    or len(material.payload_bytes) != proof.input_size_bytes
                    or tuple(material.parent_receipt_handles) != proof.parent_source_receipt_handles
                    or len(material.parent_receipts) != len(material.parent_receipt_handles)
                    or len(set(material.parent_receipt_handles)) != len(material.parent_receipt_handles)
                    or any(item.sensitivity is not Sensitivity.PUBLIC for item in material.parent_receipts)):
                raise AuthorityDenied("source.public_input", "retained public input material is incomplete")
            parent_context = material.parent_context
            if (not isinstance(parent_context, HostContext)
                    or parent_context.profile_id != proof.profile_id
                    or parent_context.principal_id != proof.principal_id
                    or parent_context.namespace_id != proof.namespace_id
                    or parent_context.generation != proof.profile_generation
                    or parent_context.native_process_identity is None
                    or parent_context.sensitivity is not Sensitivity.PUBLIC
                    or parent_context.monotonic_expires_at <= self.monotonic()
                    or tuple(parent_context.source_receipts) != tuple(material.parent_receipts)):
                raise AuthorityDenied("source.public_input", "public input parent context is not the exact public closure")

            binding = self._binding(parent_context.uid)
            self._verify_context_signature(parent_context)
            self._assert_current_context(parent_context, binding, parent_context.uid)
            parent_ids = tuple(sorted(item.receipt_id for item in material.parent_receipts))
            if (len(parent_ids) != len(set(parent_ids))
                    or any((item.uid, item.profile_id, item.principal_id, item.namespace_id,
                            item.process_generation, item.native_process_identity)
                           != (binding.uid, proof.profile_id, proof.principal_id,
                               proof.namespace_id, proof.profile_generation,
                               parent_context.native_process_identity)
                           for item in material.parent_receipts)):
                raise AuthorityDenied("source.public_input", "public source ancestry identity or closure differs")
            parent_id_set = set(parent_ids)
            if any(not set(item.parent_receipt_ids).issubset(parent_id_set)
                   for item in material.parent_receipts):
                raise AuthorityDenied("source.public_input", "public source parent closure is incomplete")

            by_handle: dict[str, SourceReceipt] = {}
            with self._lock:
                now = self.monotonic()
                for handle in material.parent_receipt_handles:
                    parent = self._source_receipt_handles.get(handle)
                    if parent is None or parent.monotonic_expires_at <= now:
                        raise AuthorityDenied("source.public_input", "a public parent receipt is no longer retained")
                    by_handle[handle] = parent
            if (tuple(by_handle[handle] for handle in material.parent_receipt_handles)
                    != tuple(material.parent_receipts)):
                raise AuthorityDenied("source.public_input", "public parent handles do not resolve to exact receipts")
            for parent in material.parent_receipts:
                self._verify_source_receipt(parent, binding)

            now = self.monotonic()
            expiry = min(now + 30.0, proof.expires_monotonic, selected_execution.expires_monotonic,
                         permission.expires_monotonic, parent_context.monotonic_expires_at)
            if not now < expiry:
                raise AuthorityDenied("source.public_input", "public input permission lease expired")
            ceilings = [frozenset(item.recipient_ceiling) for item in material.parent_receipts]
            recipients = frozenset(permission.public_recipient_ids)
            if ceilings:
                recipients = recipients.intersection(frozenset.intersection(*ceilings))
            if not recipients:
                raise AuthorityDenied("source.public_input", "verified public ancestry grants no enrolled web recipient")

            observer = source_registry.observers.get(material.source_proof.observer_enrollment_id)
            if (observer is None or observer.source_kind != "native-input"
                    or not observer.public_web_scope_ids
                    or material.source_proof.source_kind != "native-input"
                    or material.source_proof.payload_sha256 != proof.input_sha256
                    or material.source_proof.origin_id == ""):
                raise AuthorityDenied("source.public_input", "selected public source observer is unavailable")
            enrollment_id = canonical_digest({
                "uid": binding.uid, "principal_id": binding.principal_id,
                "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
                "generation": proof.profile_generation, "authority_epoch": self.authority_epoch,
            })
            receipt = SourceReceipt(
                receipt_id=secrets.token_urlsafe(24), issuer_id="host-authority",
                source_kind="native-input", principal_id=binding.principal_id,
                profile_id=binding.profile_id, namespace_id=binding.namespace_id, uid=binding.uid,
                origin_id=material.source_proof.origin_id,
                process_generation=proof.profile_generation, payload_digest=proof.input_sha256,
                sensitivity=Sensitivity.PUBLIC,
                parent_lineage_hash=parent_context.lineage_hash,
                policy_revision=self._policy_revision(), recipient_ceiling=recipients,
                issued_at_monotonic=now, monotonic_expires_at=expiry, signature="pending",
                enrollment_id=enrollment_id,
                native_process_identity=parent_context.native_process_identity,
                parent_receipt_ids=parent_ids, nonce=secrets.token_urlsafe(24),
            )
            receipt = replace(receipt, signature=self._sign(receipt.claims()))
            source_handle = SourceReceiptHandle(secrets.token_urlsafe(32))
            with self._lock:
                if len(self._source_receipt_handles) >= 100_000 or str(source_handle) in self._source_receipt_handles:
                    raise AuthorityDenied("source.capacity", "root source receipt store is unavailable")
                self._source_receipt_handles[str(source_handle)] = receipt
            retain = getattr(source_registry, "retain_selected_public_input_permission", None)
            if not callable(retain) or retain(proof, selected_execution, source_handle, permission) is not True:
                self.revoke_source_handle(source_handle)
                raise AuthorityDenied("source.public_input", "public permission linkage was not retained")
            return source_handle
        except AuthorityDenied:
            if source_handle is not None:
                try:
                    self.revoke_source_handle(source_handle)
                except Exception:
                    pass
            raise
        except Exception:
            if source_handle is not None:
                try:
                    self.revoke_source_handle(source_handle)
                except Exception:
                    pass
            raise AuthorityDenied("source.public_input", "public input source could not be authorized") from None

    def _issue_observed_source(self, observation: Any, *, selected_input_consent: Any,
                               selected_input: bool = False) -> Any:
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
        if selected_input:
            consume_proof = getattr(registry, "consume_selected_input_observation", None)
            proof_ok = (callable(consume_proof)
                        and consume_proof(observation, observation.selected_execution) is True)
        else:
            consume_proof = getattr(registry, "consume_observation_proof", None)
            proof_ok = callable(consume_proof) and consume_proof(observation) is True
        if not proof_ok:
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
        recipient_ceiling = self._source_recipient_ceiling(
            observation.source_kind, observation.parent_receipts,
            selected_input_consent=selected_input_consent,
        )
        if selected_input_consent is not None:
            parent_ceilings = [frozenset(item.recipient_ceiling) for item in observation.parent_receipts]
            if parent_ceilings:
                allowed = frozenset.intersection(*parent_ceilings)
                if not recipient_ceiling.issubset(allowed):
                    raise AuthorityDenied("source.ceiling", "private consent exceeds a verified parent recipient ceiling")
        receipt = replace(
            receipt, parent_receipt_ids=tuple(sorted(parent_ids)),
            recipient_ceiling=recipient_ceiling, signature="pending",
        )
        receipt = replace(receipt, signature=self._sign(receipt.claims()))
        handle = SourceReceiptHandle(secrets.token_urlsafe(32))
        with self._lock:
            if handle in self._source_receipt_handles:
                raise AuthorityDenied("source.capacity", "opaque source receipt handle collision")
            self._source_receipt_handles[str(handle)] = receipt
        return handle

    @staticmethod
    def _source_recipient_ceiling(source_kind: str, parent_receipts: tuple[Any, ...], *,
                                  selected_input_consent: Any = None) -> frozenset[str]:
        """Return only root-selected recipients preserved through this source edge."""
        if selected_input_consent is not None:
            recipients = getattr(selected_input_consent, "private_recipient_ids", None)
            if not isinstance(recipients, (tuple, list, set, frozenset)):
                raise AuthorityDenied("source.ceiling", "selected-input consent recipient set is invalid")
            return frozenset(recipients)
        if source_kind not in {"provider-result", "tool-result"} or not parent_receipts:
            return frozenset()
        ceilings: list[frozenset[str]] = []
        for receipt in parent_receipts:
            recipients = getattr(receipt, "recipient_ceiling", None)
            if not isinstance(recipients, (tuple, list, set, frozenset)):
                raise AuthorityDenied("source.ceiling", "verified parent recipient ceiling is invalid")
            ceilings.append(frozenset(recipients))
        # Intersection is deliberate: each ancestor must independently permit
        # a recipient. Empty and absent ceilings remain empty at every depth.
        return frozenset.intersection(*ceilings)

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
        self._revalidate_selected_input_egress(context, rule.recipient, operation)
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
        if operation == "channel.runtime.bind":
            registry = self.channel_peer_delivery_registry
            if (registry is None or peer_pidfd is None
                    or not isinstance(payload, dict) or set(payload) != {"schema"}
                    or type(payload.get("schema")) is not int or payload["schema"] != 1):
                raise AuthorityDenied("channel.binding", "selected channel peer binding is unavailable")
            return registry.bind(peer_uid=uid, peer_pid=peer_pid,
                                 peer_pidfd=peer_pidfd).to_wire()
        if operation == "channel.event.take":
            registry = self.channel_peer_delivery_registry
            expected = {"schema", "binding_handle", "max_events"}
            if (registry is None or peer_pidfd is None
                    or not isinstance(payload, dict) or set(payload) != expected
                    or type(payload.get("schema")) is not int or payload["schema"] != 1
                    or type(payload.get("max_events")) is not int or payload["max_events"] != 1
                    or not isinstance(payload.get("binding_handle"), str)):
                raise AuthorityDenied("channel.delivery", "selected channel event lookup is unavailable")
            delivery = registry.take(
                peer_uid=uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                binding_handle=payload["binding_handle"],
            )
            return delivery.to_wire() if delivery is not None else None
        if operation == "native.channel.context.take":
            store = self.native_channel_context_store
            if (store is None or peer_pidfd is None
                    or not isinstance(payload, dict)
                    or set(payload) != {"schema", "producer_context_delivery_handle"}
                    or type(payload.get("schema")) is not int or payload["schema"] != 1
                    or not isinstance(payload.get("producer_context_delivery_handle"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}",
                                        payload["producer_context_delivery_handle"])):
                raise AuthorityDenied("channel.context", "native channel context handle is unavailable")
            delivery = store.take_channel_context(
                peer_uid=uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                producer_context_delivery_handle=payload["producer_context_delivery_handle"],
            )
            result = delivery.to_wire() if delivery is not None else None
            if result is not None:
                from .native_channel_context import NativeChannelContextDelivery
                if type(delivery) is not NativeChannelContextDelivery:
                    raise AuthorityDenied("channel.context", "native channel context result is not root retained")
            return result
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
                    "turn_handle": getattr(result, "turn_handle", None),
                    "final_response_delivery_handle": getattr(result, "final_response_delivery_handle", None),
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

    def resolve_current_active_principal_binding(self, profile_id: str) -> PrincipalBinding:
        """Resolve a profile selector only against this daemon's protected activation.

        Root TTY/setup choice registries use this in-process lookup while minting
        current profile-choice receipts. The profile ID is only a selector: the
        caller cannot supply identity fields, a PrincipalBinding, a filesystem
        path, or an enrollment row. A prepared setup generation is not active
        because it has no service generation digest and no enrolled binding.
        """
        if (not isinstance(profile_id, str) or not 1 <= len(profile_id) <= 256
                or any(ord(char) < 0x21 or ord(char) > 0x7e for char in profile_id)):
            raise AuthorityDenied("principal.selection", "active profile selector is malformed")
        digest = self.service_generation_digest
        if digest is None or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AuthorityDenied("principal.selection", "no committed active service generation is loaded")
        if (set(self.bindings_by_uid) != set(self._active_binding_snapshot)
                or any(self.bindings_by_uid.get(uid) is not binding
                       for uid, binding in self._active_binding_snapshot.items())
                or self.profile_generations != self._active_profile_generation_snapshot):
            raise AuthorityDenied("principal.selection", "protected active enrollment changed after service construction")
        generation = self.profile_generations.get(profile_id)
        if not isinstance(generation, str) or not generation:
            raise AuthorityDenied("principal.selection", "profile has no active protected generation")
        matches = [binding for binding in self._active_binding_snapshot.values()
                   if type(binding) is PrincipalBinding and binding.profile_id == profile_id]
        if len(matches) != 1:
            raise AuthorityDenied("principal.selection", "active profile has no unique protected principal binding")
        binding = matches[0]
        if (self.bindings_by_uid.get(binding.uid) is not binding
                or binding.uid <= 0 or not binding.principal_id or not binding.namespace_id):
            raise AuthorityDenied("principal.selection", "active principal binding is no longer current")
        runtime = getattr(self, "root_runtime_bindings", None)
        from .runtime_bindings import RootRuntimeBindings
        catalog = getattr(runtime, "enrollment_catalog", None)
        if (type(runtime) is not RootRuntimeBindings
                or catalog is None or getattr(catalog, "digest", None) != digest
                or not callable(getattr(catalog, "resolve_profile_generation", None))):
            raise AuthorityDenied("principal.selection", "active protected service catalog is unavailable")
        try:
            selected = catalog.resolve_profile_generation(profile_id, generation)
        except Exception:
            raise AuthorityDenied("principal.selection", "profile generation is not in the active protected catalog") from None
        if (getattr(selected, "profile_id", None) != binding.profile_id
                or getattr(selected, "generation", None) != generation
                or getattr(selected, "service_uid", None) != binding.uid
                or getattr(selected, "principal_id", None) != binding.principal_id
                or getattr(selected, "namespace_identity", None) != binding.namespace_id):
            raise AuthorityDenied("principal.selection", "active service row differs from the protected principal binding")
        return binding

    def current_authority_policy_revision(self) -> str:
        """Return the current root policy revision for in-process choice receipts."""
        revision = self._policy_revision()
        if not isinstance(revision, str) or not revision:
            raise AuthorityDenied("policy.selection", "active root policy revision is unavailable")
        return revision

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
                                  owner_generation: int, ttl_seconds: int = 300,
                                  capture_consent: Any | None = None,
                                  capture_consent_handle: str | None = None,
                                  completed_turn_receipt_handle: str | None = None) -> BackgroundConsent:
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
        if any(value is not None for value in (
                capture_consent, capture_consent_handle, completed_turn_receipt_handle)):
            from .root_memory_capture_consent import RootMemoryCaptureConsent
            if (type(capture_consent) is not RootMemoryCaptureConsent
                    or not isinstance(capture_consent_handle, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", capture_consent_handle)
                    or not isinstance(completed_turn_receipt_handle, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", completed_turn_receipt_handle)
                    or capture_consent.state != "enabled"
                    or capture_consent.profile_id != context.profile_id
                    or capture_consent.namespace_id != context.namespace_id
                    or capture_consent.principal_id != context.principal_id
                    or capture_consent.provider != provider_id
                    or capture_consent.memory_owner_generation != owner_generation
                    or capture_consent.revocation_epoch < 1):
                raise AuthorityDenied("memory.consent", "persistent capture opt-in binding is invalid")
            claims.update({
                "capture_consent_handle": capture_consent_handle,
                "capture_consent_receipt_handle": capture_consent.receipt_handle,
                "capture_consent_id": capture_consent.consent_id,
                "capture_consent_revocation_epoch": capture_consent.revocation_epoch,
                "capture_consent_policy_revision": capture_consent.policy_revision,
                "completed_turn_receipt_handle": completed_turn_receipt_handle,
            })
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
        capture_fields = {"capture_consent_handle", "capture_consent_receipt_handle",
                          "capture_consent_id", "capture_consent_revocation_epoch",
                          "capture_consent_policy_revision", "completed_turn_receipt_handle"}
        if (set(consent) not in (expected, expected | capture_fields)
                or not isinstance(signature, str)):
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
        if rule is not None:
            self._revalidate_selected_input_egress(context, rule.recipient, rule.operation)
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

    def _revalidate_selected_input_egress(self, context: HostContext,
                                          recipient: str | None,
                                          operation: str) -> None:
        """Recheck root-selected private-input consent at every egress boundary.

        A signed source receipt preserves the original consent ceiling, but it
        does not preserve revocation state. Any non-null recipient effect whose
        complete lineage contains native input must therefore resolve the
        retained native selection and its current consent again immediately
        before grant issuance and effect dispatch.
        """
        if recipient is None:
            return
        input_receipts = tuple(
            receipt for receipt in context.source_receipts
            if getattr(receipt, "source_kind", None) == "native-input"
        )
        if not input_receipts:
            return
        observers = self.source_observer_registry
        resolve_selection = getattr(observers, "resolve_retained_selected_input_execution", None)
        resolve_consent = getattr(observers, "resolve_selected_input_consent", None)
        if (observers is None or not callable(resolve_selection)
                or not callable(resolve_consent)):
            raise AuthorityDenied("source.native_consent", "retained selected-input consent resolver is unavailable")
        with self._lock:
            receipt_handles: dict[str, str] = {}
            for handle, retained in self._source_receipt_handles.items():
                if retained.monotonic_expires_at > self.monotonic():
                    receipt_handles.setdefault(retained.receipt_id, handle)
        for receipt in input_receipts:
            handle = receipt_handles.get(receipt.receipt_id)
            if handle is None:
                raise AuthorityDenied("source.native_consent", "selected-input source handle is no longer retained")
            try:
                from .source_observers import SourceReceiptHandle
                root_handle = SourceReceiptHandle(handle)
                selection = resolve_selection(root_handle)
                public_selection = getattr(selection, "public_input_permission_selection_handle", None)
                if public_selection is not None:
                    if (operation != "plugin.web.read"
                            or len(input_receipts) != 1
                            or context.sensitivity is not Sensitivity.PUBLIC
                            or any(item.sensitivity is not Sensitivity.PUBLIC
                                   for item in context.source_receipts)):
                        raise AuthorityDenied("source.public_permission", "public permission cannot authorize this operation or mixed lineage")
                    resolve_public = getattr(observers, "resolve_selected_public_input_permission", None)
                    if not callable(resolve_public):
                        raise AuthorityDenied("source.public_permission", "current public permission linkage is unavailable")
                    retained = resolve_public(root_handle, selection)
                    from .root_public_input_permission import RootPublicInputPermission
                    permission = getattr(retained, "permission", None)
                    if (getattr(retained, "source_receipt_handle", None) != root_handle
                            or getattr(retained, "selected_execution", None) is not selection
                            or getattr(retained, "permission_receipt_handle", None)
                               != getattr(permission, "receipt_handle", None)
                            or type(permission) is not RootPublicInputPermission
                            or permission.retained_input_selection_handle != selection.selection_handle
                            or permission.profile_id != receipt.profile_id
                            or permission.principal_id != receipt.principal_id
                            or permission.namespace_id != receipt.namespace_id
                            or permission.profile_generation != receipt.process_generation
                            or permission.service_generation_digest != self.service_generation_digest
                            or permission.allowed_operations != ("plugin.web.read",)
                            or recipient not in permission.public_recipient_ids
                            or recipient not in receipt.recipient_ceiling
                            or permission.expires_monotonic <= self.monotonic()
                            or getattr(retained, "expires_monotonic", 0) <= self.monotonic()):
                        raise AuthorityDenied("source.public_permission", "current public permission does not cover this source and recipient")
                    self._verify_public_input_permission(permission)
                    continue
                retained_consent = resolve_consent(root_handle, selection)
            except AuthorityDenied:
                raise
            except Exception:
                raise AuthorityDenied("source.native_consent", "selected-input consent is absent or revoked") from None
            consent = getattr(retained_consent, "consent", None)
            if (getattr(retained_consent, "source_receipt_handle", None) != root_handle
                    or getattr(retained_consent, "selected_execution", None) is not selection
                    or getattr(consent, "profile_id", None) != receipt.profile_id
                    or getattr(consent, "principal_id", None) != receipt.principal_id
                    or getattr(consent, "namespace_id", None) != receipt.namespace_id
                    or getattr(consent, "service_generation_digest", None) != self.service_generation_digest
                    or consent is None
                    or recipient not in getattr(consent, "private_recipient_ids", ())
                    or recipient not in receipt.recipient_ceiling):
                raise AuthorityDenied("source.native_consent", "selected-input consent does not permit this recipient")

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
        self._revalidate_selected_input_egress(context, rule.recipient, rule.operation)
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
                request_payload=body, request_sha256=grant.request_digest,
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
        if rule.operation == "plugin.web.read":
            artifact = self._finalize_web_content_effect(
                context=context, authorization=grant, operation=rule.operation,
                target=rule.target, request_payload=body, response_status=response["status"],
                response_body=body_bytes, handler_receipt_id=receipt_id,
            )
            try:
                rendered = strict_json_loads(body_bytes.decode("utf-8", errors="strict"))
                fields = artifact.as_result_fields()
                envelope_fields = {"schema", "operation_id", "state", "result",
                                   "verification_status", "resume_action_id"}
                result = rendered.get("result") if isinstance(rendered, dict) else None
                if (not isinstance(rendered, dict) or set(rendered) != envelope_fields
                        or rendered["schema"] != 1 or rendered["state"] != "read-complete"
                        or rendered["verification_status"] != "verified"
                        or rendered["resume_action_id"] is not None
                        or not isinstance(result, dict)
                        or set(result) != {"url", "content_type", "content", "untrusted_source",
                                           "authority", "redirects", "source_receipt"}
                        or result["untrusted_source"] is not True
                        or result["authority"] != "none"
                        or not isinstance(fields, Mapping)
                        or not isinstance(result["source_receipt"], Mapping)):
                    raise ValueError
                result["source_receipt"] = dict(fields)
                body_bytes = canonical_bytes(rendered)
                if not 1 <= len(body_bytes) <= 2_097_152:
                    raise ValueError
                result["body"] = base64.b64encode(body_bytes).decode("ascii")
            except Exception:
                raise AuthorityDenied("web.content", "validated web response could not be serialized with its final receipt") from None
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
        claims = context.claims()
        if context.purpose == "resource-channel-input":
            self._verify_signature(
                {"domain": "root-channel-event-context-v129", **claims},
                context.signature,
            )
        else:
            self._verify_signature(claims, context.signature)

    def _verify_source_receipt(self, receipt: SourceReceipt, binding: PrincipalBinding,
                               *, allow_expired: bool = False) -> None:
        claims = receipt.claims()
        if receipt.issuer_id == "host-authority:root-channel-event-v129":
            self._verify_signature(
                {"domain": "root-channel-event-source-v129", **claims},
                receipt.signature,
            )
        else:
            self._verify_signature(claims, receipt.signature)
        expected_enrollment = canonical_digest({
            "uid": binding.uid, "principal_id": binding.principal_id,
            "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
            "generation": self.profile_generations.get(binding.profile_id, "unversioned"),
            "authority_epoch": self.authority_epoch,
        })
        sensitivity_valid = receipt.sensitivity in {
            Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN,
        }
        if receipt.sensitivity is Sensitivity.PUBLIC:
            sensitivity_valid = self._verify_retained_public_input_leaf(receipt)
        if (receipt.issuer_id not in {"host-authority", "host-authority:root-channel-event-v129"}
                or receipt.uid != binding.uid
                or receipt.principal_id != binding.principal_id
                or receipt.profile_id != binding.profile_id
                or receipt.namespace_id != binding.namespace_id
                or receipt.process_generation != self.profile_generations.get(binding.profile_id, "unversioned")
                or receipt.enrollment_id != expected_enrollment
                or not receipt.native_process_identity
                or receipt.nonce == ""
                or receipt.policy_revision != self._policy_revision()
                or not sensitivity_valid
                or not allow_expired and receipt.monotonic_expires_at <= self.monotonic()):
            raise AuthorityDenied("source.lineage", "source receipt is stale or bound to another host identity")

    def _verify_retained_public_input_leaf(self, receipt: SourceReceipt) -> bool:
        """Accept PUBLIC sensitivity only for the exact retained v138 input leaf."""
        if (receipt.issuer_id != "host-authority" or receipt.source_kind != "native-input"
                or not receipt.recipient_ceiling):
            return False
        observers = self.source_observer_registry
        resolve_execution = getattr(observers, "resolve_retained_selected_input_execution", None)
        resolve_permission = getattr(observers, "resolve_selected_public_input_permission", None)
        if not callable(resolve_execution) or not callable(resolve_permission):
            return False
        try:
            from .source_observers import SourceReceiptHandle
            with self._lock:
                matches = [handle for handle, retained in self._source_receipt_handles.items()
                           if retained is receipt]
            if len(matches) != 1:
                return False
            handle = SourceReceiptHandle(matches[0])
            execution = resolve_execution(handle)
            retained = resolve_permission(handle, execution)
            permission = getattr(retained, "permission", None)
            return bool(
                getattr(retained, "source_receipt_handle", None) == handle
                and getattr(retained, "selected_execution", None) is execution
                and getattr(permission, "retained_input_selection_handle", None)
                   == getattr(execution, "selection_handle", None)
                and getattr(permission, "allowed_operations", None) == ("plugin.web.read",)
                and getattr(permission, "service_generation_digest", None) == self.service_generation_digest
                and getattr(permission, "expires_monotonic", 0) > self.monotonic()
                and receipt.recipient_ceiling.issubset(set(permission.public_recipient_ids))
                and receipt.profile_id == permission.profile_id
                and receipt.principal_id == permission.principal_id
                and receipt.namespace_id == permission.namespace_id
                and receipt.process_generation == permission.profile_generation
                and receipt.payload_digest == permission.input_sha256
            )
        except Exception:
            return False

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
