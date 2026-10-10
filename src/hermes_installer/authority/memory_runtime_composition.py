"""Root-only composition helpers for selected private memory networking.

Enrollment rows select a network and endpoint; they are not a live namespace
lease.  This module is the narrow bridge from those current typed selections
to the lease retained by process custody.  It deliberately does not create a
lease, start a model, or turn the selection into a usable provider route.
"""
from __future__ import annotations

import math
import os
import time
from dataclasses import dataclass
from collections.abc import Mapping
from typing import Any, Callable

from .runtime_bindings import RootRuntimeBindings
from .private_loopback_network import RootPrivateLoopbackNetworkLease, verify_root_network_lease
from hermes_installer.protected_enrollment import EnrollmentDenied


class RootMemoryNetworkUnavailable(PermissionError):
    """The selected private network has no exact retained live lease."""


class RootMemoryNetworkLeaseResolver:
    """Resolve a protected network handle to custody's current endpoint lease.

    The public input is only the protected opaque network binding handle. The
    resolver finds exactly one selected endpoint row in the active snapshot,
    re-resolves all catalog joins, and asks the same process manager that owns
    the lease to return the retained typed object. It never accepts an
    endpoint DTO, path, namespace descriptor, or caller-supplied lease.
    """

    def __init__(self, bindings: RootRuntimeBindings, *,
                 monotonic: Callable[[], float] = time.monotonic):
        if (type(bindings) is not RootRuntimeBindings
                or not callable(monotonic)
                or bindings.enrollment_catalog is None
                or bindings.process_manager is None):
            raise RootMemoryNetworkUnavailable("active protected memory network bindings are unavailable")
        self._bindings = bindings
        self._monotonic = monotonic

    @property
    def bindings(self) -> RootRuntimeBindings:
        return self._bindings

    def resolve(self, network_binding_handle: str) -> RootPrivateLoopbackNetworkLease:
        if not isinstance(network_binding_handle, str) or not network_binding_handle:
            raise RootMemoryNetworkUnavailable("private network selector is malformed")
        try:
            endpoint = self._bindings.enrollment_catalog.resolve_private_loopback_binding_handle(
                network_binding_handle,
            )
            endpoint = self._bindings.resolve_private_memory_endpoint_binding(endpoint.binding_id)
            network = self._bindings.resolve_private_loopback_network(
                network_binding_handle,
                service_generation_digest=self._bindings.service_generation_digest,
            )
            if (endpoint.network_binding_handle != network_binding_handle
                    or endpoint.service_generation_digest != self._bindings.service_generation_digest
                    or endpoint.service_enrollment_id not in network.member_enrollment_ids
                    or endpoint.namespace_id != network.namespace_identity):
                raise ValueError("selected endpoint and network differ")
            resolve = getattr(self._bindings, "resolve_private_loopback_network_lease", None)
            if not callable(resolve):
                raise ValueError("process custody has no retained lease resolver")
            lease = resolve(network_binding_handle)
            if type(lease) is not RootPrivateLoopbackNetworkLease:
                raise ValueError("process custody returned an untyped lease")
            verify_root_network_lease(lease)
            now = self._monotonic()
            if (not math.isfinite(now) or lease.expires_monotonic <= now
                    or lease.network.network_id != network.id
                    or lease.network.generation != network.generation
                    or lease.network.service_generation_digest != network.service_generation_digest
                    or lease.network.namespace_identity != endpoint.namespace_id
                    or lease.network.members != network.member_enrollment_ids):
                raise ValueError("retained namespace lease is stale or belongs to another network")
            return lease
        except RootMemoryNetworkUnavailable:
            raise
        except Exception:
            raise RootMemoryNetworkUnavailable(
                "selected endpoint has no current custody-owned private network lease") from None

    def resolve_for_enrollment(self, enrollment: Any) -> "RootMemoryNetworkNamespaceLease":
        """Resolve the selected endpoint for one protected memory enrollment.

        This joins the service identity through the active catalog getter. It
        never scans raw rows or accepts a network selector from a caller.
        """
        from hermes_installer.memory.enrollment import MemoryServiceEnrollment
        if type(enrollment) is not MemoryServiceEnrollment:
            raise RootMemoryNetworkUnavailable("a protected memory enrollment is required")
        try:
            endpoint = self._bindings.resolve_private_memory_endpoint_for_service(
                enrollment.service_enrollment_id, enrollment.service_generation,
                enrollment.profile_id, enrollment.principal_id,
            )
            if (endpoint.service_enrollment_id != enrollment.service_enrollment_id
                    or endpoint.service_generation != enrollment.service_generation
                    or endpoint.profile_id != enrollment.profile_id
                    or endpoint.principal_id != enrollment.principal_id
                    or endpoint.namespace_id != enrollment.namespace_identity
                    or endpoint.endpoint_target_id != enrollment.target_id):
                raise ValueError("endpoint selection does not match memory enrollment")
            lease = self.resolve(endpoint.network_binding_handle)
            identity = lease.network.member(endpoint.service_enrollment_id)
            if (identity.profile_id != endpoint.process_profile_id
                    or identity.generation != endpoint.process_profile_generation):
                raise ValueError("network lease has no exact selected process member")
            view = RootMemoryNetworkNamespaceLease(
                bindings=self._bindings, endpoint=endpoint, lease=lease,
                uid=identity.uid,
            )
            view.verify_current()
            return view
        except RootMemoryNetworkUnavailable:
            raise
        except Exception:
            raise RootMemoryNetworkUnavailable(
                "memory enrollment has no exact current endpoint network lease") from None


class RootMemoryNetworkNamespaceLease:
    """Borrowed, FD-duplicated view of the retained root network lease."""

    __slots__ = ("_bindings", "_endpoint", "_lease", "_namespace_fd", "uid",
                 "generation", "namespace_identity", "closed")

    def __init__(self, *, bindings: RootRuntimeBindings, endpoint: Any,
                 lease: RootPrivateLoopbackNetworkLease, uid: int):
        if type(lease) is not RootPrivateLoopbackNetworkLease or type(uid) is not int or uid < 0:
            raise RootMemoryNetworkUnavailable("typed private network lease is required")
        self._bindings = bindings
        self._endpoint = endpoint
        self._lease = lease
        self._namespace_fd = os.dup(lease.namespace_fd)
        self.uid = uid
        self.generation = endpoint.service_generation
        self.namespace_identity = endpoint.namespace_id
        self.closed = False

    @property
    def namespace_fd(self) -> int:
        return self._namespace_fd

    def verify_current(self) -> None:
        if self.closed or self._namespace_fd < 0:
            raise RootMemoryNetworkUnavailable("private memory namespace lease view is closed")
        verify_root_network_lease(self._lease)
        endpoint = self._bindings.resolve_private_memory_endpoint_binding(
            self._endpoint.binding_id)
        lease = self._bindings.resolve_private_loopback_network_lease(
            endpoint.network_binding_handle)
        if (endpoint is not self._endpoint or lease is not self._lease
                or self._lease.network.member(endpoint.service_enrollment_id).uid != self.uid
                or self._lease.namespace_fd < 0):
            raise RootMemoryNetworkUnavailable("private memory namespace lease is no longer current")

    def close(self) -> None:
        if self._namespace_fd >= 0:
            os.close(self._namespace_fd)
            self._namespace_fd = -1
        self.closed = True


@dataclass(frozen=True, slots=True)
class RootMemoryRuntimeComposition:
    """The actual root memory graph available in one active service epoch."""

    network_lease_resolver: RootMemoryNetworkLeaseResolver | None
    prestart_receipt_registry: Any | None
    semantic_readiness_registry: Any | None
    enablement_registry: Any | None
    lifecycle_registry: Any | None
    unavailable_reason: str | None

    def close(self) -> None:
        # Custody owns network leases and the evidence registries own their
        # retained handles. Shutdown is orchestrated by their owning runtime;
        # this composition object intentionally does not close borrowed roots.
        for value in (self.lifecycle_registry, self.semantic_readiness_registry,
                      self.prestart_receipt_registry, self.enablement_registry):
            close = getattr(value, "close", None)
            if callable(close):
                close()


def compose_root_memory_runtime(*, bindings: RootRuntimeBindings,
                                enrollment: Any, memory_runtime: Any,
                                service: Any, root_setup_choice_registry: Any = None,
                                vault: Any = None,
                                network_lease_resolver: RootMemoryNetworkLeaseResolver | None = None,
                                monotonic: Callable[[], float] = time.monotonic
                                ) -> RootMemoryRuntimeComposition:
    """Compose only concrete active memory registries; otherwise report why.

    The setup choice, lifecycle consent, controller proof, private route, and
    semantic connector are separate authorities. The existing capture-consent
    registry is never accepted for service lifecycle authorization.
    """
    from .memory_lifecycle_evidence import (
        RootMemoryPrestartReceiptRegistry, RootMemorySemanticReadinessRegistry,
    )
    from .memory_lifecycle_registry import RootMemoryLifecycleRegistry
    from .root_memory_service_enablement import RootMemoryServiceEnablementRegistry
    from .root_setup_choices import RootSetupChoiceRegistry
    from hermes_installer.memory.lifecycle_authority import RootMemoryServiceLifecycle
    from hermes_installer.memory.namespace_connector import MemoryNamespaceConnector

    if type(bindings) is not RootRuntimeBindings or not enrollment.memory_enrollments:
        return RootMemoryRuntimeComposition(None, None, None, None, None,
                                            "active typed memory enrollment is unavailable")

    network_resolver = network_lease_resolver
    if network_resolver is None:
        try:
            network_resolver = RootMemoryNetworkLeaseResolver(bindings, monotonic=monotonic)
        except Exception:
            pass
    elif (type(network_resolver) is not RootMemoryNetworkLeaseResolver
          or network_resolver.bindings is not bindings):
        network_resolver = None

    prestart = semantic = enablement = lifecycle_registry = None
    journal = None
    reasons: list[str] = []
    try:
        journal = bindings.resolve_root_journal(
            "installer-authority-journal-v1",
            expected_active_generation_digest=bindings.service_generation_digest,
        )
        prestart = RootMemoryPrestartReceiptRegistry.from_root_runtime(
            bindings, bindings.artifact_catalog, bindings.process_manager, journal,
            monotonic=monotonic,
        )
    except Exception:
        reasons.append("root journal or active prestart receipt authority is unavailable")

    setup_choice_registry = root_setup_choice_registry
    setup_choices_current = (
        type(setup_choice_registry) is RootSetupChoiceRegistry
        and bindings.root_setup_choice_registry is setup_choice_registry
        and getattr(getattr(service, "root_authority_runtime", None),
                    "root_setup_choice_registry", None) is setup_choice_registry
        and callable(getattr(
            setup_choice_registry, "resolve_current_memory_service_enablement_choice", None,
        ))
    )
    if not setup_choices_current:
        reasons.append("durable root service-enable choice registry is unavailable")
    if setup_choices_current and journal is not None:
        try:
            enablement = RootMemoryServiceEnablementRegistry.from_root_runtime(
                bindings, setup_choice_registry, journal,
            )
        except Exception:
            reasons.append("active service-enable choice does not resolve against the protected generation")

    semantic_connector = None
    if network_resolver is not None and vault is not None:
        try:
            candidate_connector = (memory_runtime.get("namespace_connector")
                                   if isinstance(memory_runtime, Mapping) else None)
            if (type(candidate_connector) is MemoryNamespaceConnector
                    and candidate_connector.private_network_lease_resolver is network_resolver):
                semantic_connector = candidate_connector
            else:
                semantic_connector = MemoryNamespaceConnector(
                    catalog=bindings.enrollment_catalog,
                    process_manager=bindings.process_manager,
                    vault=vault,
                    private_network_lease_resolver=network_resolver,
                    monotonic=monotonic,
                )
            if isinstance(memory_runtime, dict):
                memory_runtime["namespace_connector"] = semantic_connector
        except Exception:
            semantic_connector = None
    if type(semantic_connector) is not MemoryNamespaceConnector:
        reasons.append("root memory namespace connector with a retained private-network lease is unavailable")
    elif prestart is not None:
        try:
            semantic = RootMemorySemanticReadinessRegistry.from_root_runtime(
                bindings, bindings.process_manager, semantic_connector, journal,
                prestart_registry=prestart, monotonic=monotonic,
            )
        except Exception:
            reasons.append("semantic readiness registry rejected the active connector or journal")

    if enablement is None:
        # A process-local setup TTY receipt and capture consent are not a
        # durable active service-enable choice.
        reasons.append("memory lifecycle remains disabled without durable setup-choice verification")
    lifecycle_consent_registry = getattr(service, "memory_lifecycle_consent_registry", None)
    controller_proof_resolver = getattr(service, "memory_controller_proof_resolver", None)
    private_route_resolver = getattr(service, "private_memory_route_resolver", None)
    if (enablement is not None
          and callable(getattr(lifecycle_consent_registry, "resolve_current_lifecycle_consent", None))
          and callable(getattr(controller_proof_resolver, "resolve_memory_controller_proof", None))
          and callable(getattr(private_route_resolver, "resolve_selected_memory_engine", None))
          and semantic is not None and prestart is not None
          and type(getattr(service, "root_memory_service_lifecycle", None)) is RootMemoryServiceLifecycle):
        try:
            lifecycle_registry = RootMemoryLifecycleRegistry.from_root_runtime(
                active_bindings=bindings,
                lifecycle=service.root_memory_service_lifecycle,
                source_receipt_registry=prestart,
                lifecycle_consent_registry=lifecycle_consent_registry,
                controller_proof_resolver=controller_proof_resolver,
                private_route_resolver=private_route_resolver,
                enablement_registry=enablement,
                connector_registry=semantic,
                monotonic=monotonic,
            )
        except Exception:
            reasons.append("typed memory lifecycle registries failed their active-root identity checks")
    else:
        reasons.append("memory lifecycle consent, controller proof, private route, or service lifecycle is unavailable")

    return RootMemoryRuntimeComposition(
        network_lease_resolver=network_resolver,
        prestart_receipt_registry=prestart,
        semantic_readiness_registry=semantic,
        enablement_registry=enablement,
        lifecycle_registry=lifecycle_registry,
        unavailable_reason="; ".join(dict.fromkeys(reasons)) if reasons else None,
    )
