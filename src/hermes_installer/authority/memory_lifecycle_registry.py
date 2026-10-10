"""Root-selected memory lifecycle admission and startup orchestration.

This is the only public root-local path that turns an active memory enrollment
into a managed service start.  Every authority input is resolved from a
root-owned registry at admission and re-resolved for currentness; caller input
is limited to opaque references issued by those registries.

The capture-consent registry is intentionally not accepted here: permission to
capture a turn does not authorize installing or starting a service.
"""
from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from hermes_installer.memory.enrollment import MemoryServiceEnrollment
from hermes_installer.memory.lifecycle_authority import (
    MemoryLifecycleDenied,
    MemorySelectedLifecycleActionBinding,
    RootMemoryServiceLifecycle,
    RootVerifiedMemoryLifecycleAdmission,
)
from hermes_installer.authority.memory_lifecycle_evidence import (
    RootMemoryPrestartReceiptRegistry,
    RootMemorySemanticReadinessRegistry,
)
from hermes_installer.authority.root_memory_service_enablement import (
    RootMemoryServiceEnablementRegistry,
    RootMemoryServiceEnablementSelection,
)


class RootMemoryLifecycleRegistryDenied(PermissionError):
    """A selected memory lifecycle lacks current root-owned evidence."""


@dataclass(frozen=True, slots=True, repr=False)
class RootMemoryServiceStartReceipt:
    """Root-private actual start and backend-semantic evidence.

    The receipt only records an actual selected provider search operation. A
    provider status route, `state=running`, or this receipt alone does not
    prove private extraction or embedding deployment availability.
    """

    schema: int
    receipt_handle: str
    admission_handle: str
    provider: str
    profile_id: str
    service_enrollment_id: str
    service_generation: str
    service_generation_digest: str
    process_id: str
    start_operation_id: str
    prestart_receipt_handles: tuple[str, ...]
    readiness_receipt_handle: str | None
    readiness_kind: str
    readiness_route_id: str | None
    readiness_schema_id: str | None
    issued_monotonic: float
    expires_monotonic: float
    _start_receipt: Any = field(repr=False, compare=False)
    _readiness_receipt: Any = field(default=None, repr=False, compare=False)
    _is_current: Callable[[], bool] = field(default=lambda: False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self.schema != 1 or not all(isinstance(value, str) and value for value in (
                self.receipt_handle, self.admission_handle, self.provider, self.profile_id,
                self.service_enrollment_id, self.service_generation,
                self.service_generation_digest, self.process_id, self.start_operation_id))
                or self.readiness_kind not in {"pending", "route-ready", "liveness-only", "backend-semantic"}
                or type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or self.expires_monotonic <= self.issued_monotonic
                or not callable(self._is_current)):
            raise RootMemoryLifecycleRegistryDenied("memory start receipt is malformed")

    def is_current(self) -> bool:
        try:
            return time.monotonic() < self.expires_monotonic and bool(self._is_current())
        except Exception:
            return False

    def __repr__(self) -> str:
        return "RootMemoryServiceStartReceipt(<root-private>)"


class RootMemoryLifecycleRegistry:
    """Resolve current enrollment evidence and drive the fixed root lifecycle.

    Required collaborators are purpose-specific public root registries:

    * ``source_receipt_registry.resolve_memory_prestart_closure`` returns a
      retained source-closure object for the enrollment's exact prestart
      receipt handles and active service digest.
    * ``enablement_registry.resolve_selected_enablement`` revalidates the
      durable root TTY service-enable choice, separately from capture and
      provider-route choices.
    * ``lifecycle_consent_registry.resolve_current_lifecycle_consent`` returns
      explicit service-start consent for this enrollment and profile.
    * ``controller_proof_resolver.resolve_memory_controller_proof`` returns a
      live PIDFD lease for the actual root controller process.
    * ``private_route_resolver.resolve_selected_memory_engine`` validates the
      selected private extraction and embedding routes and model deployments.
    * ``connector_registry.probe_selected_readiness`` invokes only the exact
      source-pinned route in the supervised service namespace.

    These ports deliberately have no defaults. In particular, an absent
    consent, source, route, deployment, or process proof keeps the service
    unavailable instead of creating a success-shaped fixture.
    """

    def __init__(self, *, bindings: Any, lifecycle: RootMemoryServiceLifecycle,
                 source_receipt_registry: Any, lifecycle_consent_registry: Any,
                 controller_proof_resolver: Any, private_route_resolver: Any,
                 enablement_registry: Any = None,
                 connector_registry: Any, monotonic: Callable[[], float] = time.monotonic):
        required = (
            (bindings, "resolve_memory_enrollment"),
            (source_receipt_registry, "resolve_memory_prestart_closure"),
            (lifecycle_consent_registry, "resolve_current_lifecycle_consent"),
            (controller_proof_resolver, "resolve_memory_controller_proof"),
            (private_route_resolver, "resolve_selected_memory_engine"),
            (connector_registry, "probe_selected_readiness"),
        )
        if (type(lifecycle) is not RootMemoryServiceLifecycle
                or not callable(monotonic)
                or type(source_receipt_registry) is not RootMemoryPrestartReceiptRegistry
                or type(connector_registry) is not RootMemorySemanticReadinessRegistry
                or type(enablement_registry) is not RootMemoryServiceEnablementRegistry
                or any(not callable(getattr(owner, method, None)) for owner, method in required)):
            raise RootMemoryLifecycleRegistryDenied("root memory lifecycle evidence registries are unavailable")
        self.bindings = bindings
        self.lifecycle = lifecycle
        self.source_receipt_registry = source_receipt_registry
        self.lifecycle_consent_registry = lifecycle_consent_registry
        self.enablement_registry = enablement_registry
        self.controller_proof_resolver = controller_proof_resolver
        self.private_route_resolver = private_route_resolver
        self.connector_registry = connector_registry
        self.monotonic = monotonic
        self._lock = threading.RLock()
        self._admissions: dict[str, RootVerifiedMemoryLifecycleAdmission] = {}
        self._source_closures: dict[str, Any] = {}
        self._consents: dict[str, Any] = {}
        self._routes: dict[str, Any] = {}
        self._start_receipts: dict[str, Any] = {}
        self._readiness_receipts: dict[str, Any] = {}
        self._receipts: dict[str, RootMemoryServiceStartReceipt] = {}
        # Control re-admission is keyed by the exact opaque manager receipt
        # object. The associated user-selected handles are retained here only
        # so the registry can re-resolve current evidence; callers never pass
        # controller, source, or consent selectors again.
        self._control_origins: dict[str, tuple[str, str, str, str, Any]] = {}
        self._control_admissions: dict[str, tuple[RootVerifiedMemoryLifecycleAdmission, Any, str]] = {}
        self._authority_handles: dict[str, tuple[str, str]] = {}

    @classmethod
    def from_root_runtime(cls, *, active_bindings: Any, lifecycle: RootMemoryServiceLifecycle,
                          source_receipt_registry: Any, lifecycle_consent_registry: Any,
                          controller_proof_resolver: Any, private_route_resolver: Any,
                          enablement_registry: Any = None,
                          connector_registry: Any,
                          monotonic: Callable[[], float] = time.monotonic
                          ) -> "RootMemoryLifecycleRegistry":
        """Construct from the active root runtime's concrete registries."""
        return cls(
            bindings=active_bindings, lifecycle=lifecycle,
            source_receipt_registry=source_receipt_registry,
            lifecycle_consent_registry=lifecycle_consent_registry,
            controller_proof_resolver=controller_proof_resolver,
            private_route_resolver=private_route_resolver,
            enablement_registry=enablement_registry,
            connector_registry=connector_registry, monotonic=monotonic,
        )

    def _active_digest(self) -> str:
        digest = getattr(getattr(self.bindings, "enrollment_catalog", None), "digest", None)
        if not isinstance(digest, str) or len(digest) != 64:
            raise RootMemoryLifecycleRegistryDenied("active protected service generation is unavailable")
        return digest

    def _resolve_evidence(self, memory_enrollment_id: str, consent_handle: str,
                          controller_proof_handle: str) -> tuple[Any, ...]:
        digest = self._active_digest()
        enrollment = self.bindings.resolve_memory_enrollment(
            memory_enrollment_id, service_generation_digest=digest)
        if type(enrollment) is not MemoryServiceEnrollment or enrollment.lifecycle_binding is None:
            raise RootMemoryLifecycleRegistryDenied("strict active memory lifecycle enrollment is unavailable")
        binding = enrollment.lifecycle_binding
        source = self.source_receipt_registry.resolve_memory_prestart_closure(
            enrollment, binding.prestart_receipt_handles,
            service_generation_digest=digest)
        source_handles = getattr(source, "receipt_handles", None)
        source_sha256 = getattr(source, "source_closure_sha256", None)
        if (not callable(getattr(source, "is_current", None)) or not source.is_current()
                or source_handles != binding.prestart_receipt_handles
                or not isinstance(source_sha256, str) or len(source_sha256) != 64):
            raise RootMemoryLifecycleRegistryDenied("current verified memory prestart closure is unavailable")
        selection = self.enablement_registry.resolve_selected_enablement(memory_enrollment_id)
        if (type(selection) is not RootMemoryServiceEnablementSelection
                or not self.enablement_registry.is_current(selection)
                or selection.selection_handle != source.enablement_selection_handle
                or selection.principal_id != enrollment.principal_id
                or selection.profile_id != enrollment.profile_id
                or selection.namespace_id != enrollment.namespace_identity
                or selection.provider != enrollment.provider
                or selection.backend_variant != enrollment.backend_variant
                or selection.service_enrollment_id != enrollment.service_enrollment_id
                or selection.service_generation != enrollment.service_generation
                or selection.memory_owner_generation != enrollment.memory_owner_generation
                or selection.start_operation_id != binding.start_operation_id):
            raise RootMemoryLifecycleRegistryDenied(
                "current explicit root memory service enablement is unavailable")
        consent = self.lifecycle_consent_registry.resolve_current_lifecycle_consent(
            consent_handle, enrollment, service_generation_digest=digest)
        if (not callable(getattr(consent, "is_current", None)) or not consent.is_current()
                or getattr(consent, "profile_id", None) != enrollment.profile_id
                or getattr(consent, "service_enrollment_id", None) != enrollment.service_enrollment_id
                or getattr(consent, "consent_revision", None) != enrollment.background_consent_revision
                or getattr(consent, "purpose", None) != "memory-service-lifecycle"):
            raise RootMemoryLifecycleRegistryDenied("explicit current memory lifecycle consent is unavailable")
        routes = self.private_route_resolver.resolve_selected_memory_engine(
            memory_enrollment_id, enrollment.memory_owner_generation)
        if (not self.private_route_resolver.is_current(routes)
                or getattr(routes, "profile_id", None) != enrollment.profile_id
                or getattr(routes, "namespace_id", None) != enrollment.namespace_identity
                or getattr(routes, "memory_owner_generation", None) != enrollment.memory_owner_generation
                or getattr(routes, "service_generation_digest", None) != digest):
            raise RootMemoryLifecycleRegistryDenied("selected private extraction and embedding deployments are stale")
        controller = self.controller_proof_resolver.resolve_memory_controller_proof(
            controller_proof_handle, enrollment,
            service_generation_digest=digest)
        from hermes_installer.authority.selected_startup_authority import RootControllerProcessIdentityLease
        if (type(controller) is not RootControllerProcessIdentityLease or not controller.is_current()):
            raise RootMemoryLifecycleRegistryDenied("live root lifecycle controller PIDFD proof is unavailable")
        return digest, enrollment, source, consent, routes, controller, selection

    def admit_selected_memory(self, memory_enrollment_id: str, consent_handle: str,
                              controller_proof_handle: str) -> str:
        """Create a sealed, current admission from root-resolved evidence."""
        if not all(isinstance(value, str) and value for value in (
                memory_enrollment_id, consent_handle, controller_proof_handle)):
            raise RootMemoryLifecycleRegistryDenied("opaque selected memory references are required")
        now = self.monotonic()
        digest, enrollment, source, consent, routes, controller, selection = self._resolve_evidence(
            memory_enrollment_id, consent_handle, controller_proof_handle)
        source_sha256 = source.source_closure_sha256
        source_handles = tuple(source.receipt_handles)
        service_catalog = self.bindings.enrollment_catalog
        actions = {
            action: MemorySelectedLifecycleActionBinding.resolve(
                enrollment, service_catalog, action=action,
                source_closure_sha256=source_sha256,
                source_receipt_handles=source_handles,
            ) for action in ("start", "status", "stop")
        }
        consent_deadline = getattr(consent, "expires_monotonic", None)
        route_deadline = getattr(routes, "expires_monotonic", None)
        source_deadline = getattr(source, "expires_monotonic", None)
        deadlines = (consent_deadline, route_deadline, source_deadline, controller.expires_monotonic)
        if any(isinstance(value, bool) or type(value) not in (int, float)
               or not math.isfinite(value) or value <= now for value in deadlines):
            controller.close()
            raise RootMemoryLifecycleRegistryDenied("one or more selected memory evidence leases expired")
        life = enrollment.lifecycle_binding
        original_deadline = min(now + life.original_deadline_seconds, *deadlines)
        expires = min(original_deadline, now + 30.0)
        if expires <= now:
            controller.close()
            raise RootMemoryLifecycleRegistryDenied("selected memory lifecycle deadline is exhausted")

        # The closure is installed before admission retention, but the exact
        # admission object is captured below so currentness cannot be caller-set.
        holder: dict[str, RootVerifiedMemoryLifecycleAdmission] = {}

        def current_check(admission: RootVerifiedMemoryLifecycleAdmission) -> bool:
            retained = holder.get("admission")
            if retained is not admission:
                return False
            current_controller = None
            try:
                current = self._resolve_evidence(memory_enrollment_id, consent_handle,
                                                 controller_proof_handle)
                current_controller = current[5]
                return (current[0] == admission.service_generation_digest
                        and current[1] == enrollment
                        and current[2] is source and current[3] is consent
                        and current[4] == routes and current[5] is controller
                        and current[6] == selection
                        and source.is_current() and consent.is_current()
                        and self.enablement_registry.is_current(selection)
                        and self.private_route_resolver.is_current(routes)
                        and controller.is_current())
            except Exception:
                return False
            finally:
                if current_controller is not None and current_controller is not controller:
                    current_controller.close()

        try:
            admission = RootVerifiedMemoryLifecycleAdmission._from_root_registry(
                service_generation_digest=digest, enrollment=enrollment,
                consent_id=consent.consent_id, consent_revision=consent.consent_revision,
                source_closure_sha256=source_sha256, source_receipt_handles=source_handles,
                sensitivity="PRIVATE", issued_monotonic=now,
                expires_monotonic=expires, original_deadline=original_deadline,
                action_bindings=actions, controller_lease=controller,
                consent_record=consent, source_closure=source,
                current_check=current_check,
            )
            holder["admission"] = admission
            self.lifecycle.retain_admission(admission)
            if not admission.is_current(now=self.monotonic()):
                raise RootMemoryLifecycleRegistryDenied("selected memory evidence changed during admission")
        except Exception:
            controller.close()
            raise
        with self._lock:
            self._admissions[admission.admission_handle] = admission
            self._source_closures[admission.admission_handle] = source
            self._consents[admission.admission_handle] = consent
            self._routes[admission.admission_handle] = routes
            self._authority_handles[admission.admission_handle] = (
                consent_handle, controller_proof_handle)
        return admission.admission_handle

    def resolve_admission(self, admission_handle: str) -> RootVerifiedMemoryLifecycleAdmission:
        with self._lock:
            admission = self._admissions.get(admission_handle)
        if type(admission) is not RootVerifiedMemoryLifecycleAdmission or not admission.is_current(
                now=self.monotonic()):
            raise RootMemoryLifecycleRegistryDenied("selected memory lifecycle admission is stale")
        return admission

    def start_selected_memory(self, admission_handle: str, *, timeout: float = 30.0,
                              cancelled: Callable[[], bool] | None = None
                              ) -> RootMemoryServiceStartReceipt:
        """Start the selected recipe and collect actual process and route evidence."""
        admission = self.resolve_admission(admission_handle)
        start_receipt = self.lifecycle.start_selected_memory(
            admission_handle, timeout=timeout, cancelled=cancelled)
        process_id = self.lifecycle._process_id_from_receipt(start_receipt, admission)
        # Process identity is independently re-resolved by custody. A returned
        # process id by itself is never accepted as evidence of a live process.
        resolve_process = getattr(self.lifecycle.custody, "resolve_selected_service_process", None)
        if not callable(resolve_process):
            raise RootMemoryLifecycleRegistryDenied("managed process identity resolver is unavailable")
        managed_process = resolve_process(start_receipt)
        if managed_process is None:
            raise RootMemoryLifecycleRegistryDenied("managed memory service process is not current")
        try:
            probe = self.connector_registry.probe_selected_readiness(
                admission._enrollment,
                route_id=admission._enrollment.lifecycle_binding.readiness_route_id,
                schema_id=admission._enrollment.lifecycle_binding.readiness_schema_id,
                process_receipt=start_receipt,
                process_identity=managed_process,
                deadline=admission.original_deadline,
            )
            if (probe is None or not callable(getattr(probe, "is_current", None))
                    or not probe.is_current()
                    or getattr(probe, "readiness_kind", None) != "backend-semantic"
                    or getattr(probe, "route_id", None) not in {
                        "openviking-find", "agentmemory-search"}
                    or getattr(probe, "schema_id", None) not in {
                        getattr(admission._enrollment.fixed_route_map.get("openviking-find"),
                                "result_schema_id", None),
                        getattr(admission._enrollment.fixed_route_map.get("agentmemory-search"),
                                "result_schema_id", None)}):
                raise RootMemoryLifecycleRegistryDenied("actual selected memory semantic operation was not verified")
        except Exception:
            raise RootMemoryLifecycleRegistryDenied("selected memory readiness could not be verified") from None
        finally:
            close = getattr(managed_process, "close", None)
            if callable(close):
                close()
        if not admission.is_current(now=self.monotonic()):
            raise RootMemoryLifecycleRegistryDenied("selected memory evidence expired after readiness probe")
        # A provider's status route is never promoted. Only an actual selected
        # semantic operation result can make the service backend-semantic.
        readiness_kind = getattr(probe, "readiness_kind", None)
        if readiness_kind != "backend-semantic":
            raise RootMemoryLifecycleRegistryDenied("readiness validator returned an unknown evidence class")
        handle = __import__("secrets").token_urlsafe(32)
        def current_receipt() -> bool:
            if not admission.is_current(now=self.monotonic()) or not probe.is_current():
                return False
            lease = self.lifecycle.custody.resolve_selected_service_process(start_receipt)
            if lease is None:
                return False
            try:
                # resolve_selected_service_process performs the live custody
                # and PIDFD checks before returning this short-lived duplicate.
                return (getattr(lease, "process_id", None) == process_id
                        and getattr(lease, "generation", None) == admission.generation
                        and getattr(lease, "expires_monotonic", 0) > self.monotonic())
            finally:
                close = getattr(lease, "close", None)
                if callable(close):
                    close()

        receipt = RootMemoryServiceStartReceipt(
            schema=1, receipt_handle=handle,
            admission_handle=admission.admission_handle,
            provider=admission._enrollment.provider,
            profile_id=admission.profile_id,
            service_enrollment_id=admission.service_enrollment_id,
            service_generation=admission.generation,
            service_generation_digest=admission.service_generation_digest,
            process_id=process_id,
            start_operation_id=admission.action_bindings["start"].operation_id,
            prestart_receipt_handles=admission._enrollment.lifecycle_binding.prestart_receipt_handles,
            readiness_receipt_handle=probe.receipt_handle,
            readiness_kind=readiness_kind,
            readiness_route_id=probe.route_id,
            readiness_schema_id=probe.schema_id,
            issued_monotonic=self.monotonic(),
            expires_monotonic=min(admission.expires_monotonic, probe.expires_monotonic),
            _start_receipt=start_receipt, _readiness_receipt=probe,
            _is_current=current_receipt,
        )
        with self._lock:
            self._start_receipts[admission_handle] = start_receipt
            self._readiness_receipts[admission_handle] = probe
            self._receipts[handle] = receipt
            from hermes_installer.managed_process_custodian import RootSelectedServiceProcessReceipt
            if type(start_receipt) is RootSelectedServiceProcessReceipt:
                self._control_origins[start_receipt.receipt_handle] = (
                    admission._enrollment.target_id,
                    self._consent_handle_for(admission_handle),
                    self._controller_handle_for(admission_handle),
                    admission_handle,
                    start_receipt,
                )
        return receipt

    def _consent_handle_for(self, admission_handle: str) -> str:
        return self._authority_handles[admission_handle][0]

    def _controller_handle_for(self, admission_handle: str) -> str:
        return self._authority_handles[admission_handle][1]

    def readmit_selected_control(self, memory_enrollment_id: str, owned_process_handle: Any,
                                 operation: str) -> RootVerifiedMemoryLifecycleAdmission:
        """Mint a fresh <=30s status/stop admission for one retained process.

        The caller can select only the active enrollment and a finite control
        operation. Process identity, original deadline, source closure,
        enablement, consent and controller PIDFD are re-resolved from root
        registries and the exact object retained at start.
        """
        from hermes_installer.managed_process_custodian import RootSelectedServiceProcessReceipt
        from hermes_installer.authority.memory_lifecycle_evidence import _managed_identity_digest
        action = {"process.status": "status", "process.stop": "stop"}.get(operation)
        if (action is None
                or type(owned_process_handle) is not RootSelectedServiceProcessReceipt
                or not isinstance(memory_enrollment_id, str) or not memory_enrollment_id):
            raise RootMemoryLifecycleRegistryDenied("typed retained process and finite control operation are required")
        receipt = owned_process_handle
        with self._lock:
            origin = self._control_origins.get(receipt.receipt_handle)
        if (origin is None or origin[4] is not receipt or origin[0] != memory_enrollment_id):
            raise RootMemoryLifecycleRegistryDenied("process receipt is not the exact retained memory start")
        enrollment_id, consent_handle, controller_handle, start_handle, _ = origin
        original = self._admissions.get(start_handle)
        if (type(original) is not RootVerifiedMemoryLifecycleAdmission
                or original._enrollment.target_id != enrollment_id
                or original.original_deadline != receipt.expires_monotonic
                or receipt.action != "start"
                or receipt.operation_id != original.action_bindings["start"].operation_id
                or receipt.role != f"memory-{original._enrollment.provider}"
                or receipt.enrollment_id != original.service_enrollment_id
                or receipt.profile_id != original.profile_id
                or receipt.generation != original.generation
                or receipt.selected_principal_id != original.principal_id
                or receipt.selected_namespace_identity != original.namespace_identity
                or receipt.service_generation_digest != original.service_generation_digest
                or self.monotonic() >= receipt.expires_monotonic):
            raise RootMemoryLifecycleRegistryDenied("original process lineage or deadline is stale")
        process_resolver = getattr(self.lifecycle.custody, "resolve_selected_service_process", None)
        if not callable(process_resolver):
            raise RootMemoryLifecycleRegistryDenied("manager-owned process identity resolver is unavailable")
        live = process_resolver(receipt)
        if live is None:
            raise RootMemoryLifecycleRegistryDenied("retained selected service process is no longer current")
        try:
            if (getattr(live, "process_id", None) != receipt.process_id
                    or getattr(live, "generation", None) != receipt.generation
                    or getattr(live, "profile_id", None) != receipt.profile_id
                    or getattr(live, "uid", None) != receipt.selected_subject_uid
                    or getattr(live, "gid", None) != receipt.selected_subject_gid
                    or getattr(live, "expires_monotonic", 0) != receipt.expires_monotonic):
                raise RootMemoryLifecycleRegistryDenied("retained process identity differs from its start receipt")
        finally:
            close = getattr(live, "close", None)
            if callable(close):
                close()

        now = self.monotonic()
        digest, enrollment, source, consent, routes, controller, selection = self._resolve_evidence(
            enrollment_id, consent_handle, controller_handle)
        source_sha256 = source.source_closure_sha256
        if (digest != original.service_generation_digest
                or enrollment != original._enrollment
                or source_sha256 != original.source_closure_sha256
                or tuple(source.receipt_handles) != original.source_receipt_handles
                or consent.consent_id != original.consent_id
                or consent.consent_revision != original.consent_revision
                or selection.selection_handle != source.enablement_selection_handle):
            controller.close()
            raise RootMemoryLifecycleRegistryDenied("fresh control evidence differs from the original process admission")
        deadlines = (getattr(consent, "expires_monotonic", None),
                    getattr(routes, "expires_monotonic", None),
                    getattr(source, "expires_monotonic", None),
                    controller.expires_monotonic, receipt.expires_monotonic)
        if any(isinstance(value, bool) or type(value) not in (int, float)
               or not math.isfinite(value) or value <= now for value in deadlines):
            controller.close()
            raise RootMemoryLifecycleRegistryDenied("fresh control evidence lease is exhausted")
        expires = min(now + 30.0, *deadlines)
        try:
            actions = {
                action: MemorySelectedLifecycleActionBinding.resolve(
                    enrollment, self.bindings.enrollment_catalog, action=action,
                    source_closure_sha256=source_sha256,
                    source_receipt_handles=tuple(source.receipt_handles),
                    process_id=receipt.process_id if action in {"status", "stop"} else None,
                ) for action in ("start", "status", "stop")
            }
        except Exception:
            controller.close()
            raise RootMemoryLifecycleRegistryDenied(
                "fresh process control recipe is unavailable") from None
        if expires <= now:
            controller.close()
            raise RootMemoryLifecycleRegistryDenied("fresh control admission has no live lease")

        holder: dict[str, RootVerifiedMemoryLifecycleAdmission] = {}

        def same_controller(fresh: Any, retained: Any) -> bool:
            return (getattr(fresh, "proof_sha256", None) == getattr(retained, "proof_sha256", None)
                    and getattr(fresh, "pid", None) == getattr(retained, "pid", None)
                    and getattr(fresh, "start_ticks", None) == getattr(retained, "start_ticks", None)
                    and getattr(fresh, "cgroup_identity", None) == getattr(retained, "cgroup_identity", None)
                    and getattr(fresh, "mount_namespace_inode", None) == getattr(retained, "mount_namespace_inode", None)
                    and getattr(fresh, "network_namespace_inode", None) == getattr(retained, "network_namespace_inode", None))

        def current_check(admission: RootVerifiedMemoryLifecycleAdmission) -> bool:
            if holder.get("admission") is not admission or self.monotonic() >= receipt.expires_monotonic:
                return False
            fresh_controller = None
            fresh_process = None
            try:
                current = self._resolve_evidence(enrollment_id, consent_handle, controller_handle)
                fresh_controller = current[5]
                if (current[0] != digest or current[1] != enrollment
                        or current[2].source_closure_sha256 != source_sha256
                        or tuple(current[2].receipt_handles) != tuple(source.receipt_handles)
                        or current[3].consent_id != consent.consent_id
                        or current[3].consent_revision != consent.consent_revision
                        or current[6].selection_handle != selection.selection_handle
                        or not same_controller(fresh_controller, controller)
                        or not controller.is_current()):
                    return False
                fresh_process = process_resolver(receipt)
                return bool(fresh_process is not None
                            and fresh_process.process_id == receipt.process_id
                            and fresh_process.generation == receipt.generation
                            and fresh_process.profile_id == receipt.profile_id
                            and fresh_process.uid == receipt.selected_subject_uid
                            and fresh_process.gid == receipt.selected_subject_gid
                            and fresh_process.expires_monotonic == receipt.expires_monotonic
                            and _managed_identity_digest(fresh_process) == receipt.process_identity_digest)
            except Exception:
                return False
            finally:
                if fresh_controller is not None and fresh_controller is not controller:
                    fresh_controller.close()
                if fresh_process is not None:
                    fresh_process.close()

        try:
            admission = RootVerifiedMemoryLifecycleAdmission._from_root_registry(
                service_generation_digest=digest, enrollment=enrollment,
                consent_id=consent.consent_id, consent_revision=consent.consent_revision,
                source_closure_sha256=source_sha256,
                source_receipt_handles=tuple(source.receipt_handles), sensitivity="PRIVATE",
                issued_monotonic=now, expires_monotonic=expires,
                original_deadline=receipt.expires_monotonic, action_bindings=actions,
                controller_lease=controller, consent_record=consent,
                source_closure=source, current_check=current_check,
            )
            holder["admission"] = admission
            self.lifecycle.retain_admission(admission)
            if not admission.is_current(now=self.monotonic()):
                raise RootMemoryLifecycleRegistryDenied("fresh process-control evidence changed during readmission")
        except Exception:
            controller.close()
            raise
        with self._lock:
            self._admissions[admission.admission_handle] = admission
            self._source_closures[admission.admission_handle] = source
            self._consents[admission.admission_handle] = consent
            self._routes[admission.admission_handle] = routes
            self._control_admissions[admission.admission_handle] = (admission, receipt, operation)
            self._authority_handles[admission.admission_handle] = (consent_handle, controller_handle)
        # The old controller lease cannot authorize later operations. Release
        # it after a fresh proof has been retained; the immutable old object is
        # kept only as lineage metadata in this registry.
        release = getattr(self.lifecycle, "release_admission", None)
        if callable(release):
            release(start_handle)
        return admission

    def perform_selected_control(self, admission: RootVerifiedMemoryLifecycleAdmission,
                                 owned_process_handle: Any, operation: str, *,
                                 reason: str = "shutdown", timeout: float = 10.0,
                                 cancelled: Callable[[], bool] | None = None) -> Any:
        """Execute only the exact fresh control admission returned above."""
        from hermes_installer.managed_process_custodian import RootSelectedServiceProcessReceipt
        retained = self._control_admissions.get(getattr(admission, "admission_handle", ""))
        action = {"process.status": "status", "process.stop": "stop"}.get(operation)
        if (action is None or type(admission) is not RootVerifiedMemoryLifecycleAdmission
                or retained is None or retained[0] is not admission
                or retained[1] is not owned_process_handle or retained[2] != operation
                or type(owned_process_handle) is not RootSelectedServiceProcessReceipt
                or not admission.is_current(now=self.monotonic())):
            raise RootMemoryLifecycleRegistryDenied("fresh process-control admission is absent or stale")
        if action == "stop" and reason != "shutdown":
            raise RootMemoryLifecycleRegistryDenied("only the fixed shutdown stop reason is available here")
        binding = admission.action(action, now=self.monotonic(),
                                  reason=reason if action == "stop" else None)
        binding = binding.with_retained_process(owned_process_handle.process_id)
        try:
            return self.lifecycle._effect(admission, binding, timeout=timeout, cancelled=cancelled)
        finally:
            release = getattr(self.lifecycle, "release_admission", None)
            if callable(release):
                release(admission.admission_handle)
            with self._lock:
                self._control_admissions.pop(admission.admission_handle, None)
                self._admissions.pop(admission.admission_handle, None)
                self._source_closures.pop(admission.admission_handle, None)
                self._consents.pop(admission.admission_handle, None)
                self._routes.pop(admission.admission_handle, None)
                self._authority_handles.pop(admission.admission_handle, None)
                if action == "stop":
                    origin = self._control_origins.get(owned_process_handle.receipt_handle)
                    if origin is not None and origin[4] is owned_process_handle:
                        self._control_origins.pop(owned_process_handle.receipt_handle, None)
                        old_handle = origin[3]
                        self._admissions.pop(old_handle, None)
                        self._source_closures.pop(old_handle, None)
                        self._consents.pop(old_handle, None)
                        self._routes.pop(old_handle, None)
                        self._authority_handles.pop(old_handle, None)

    def control_selected_memory(self, memory_enrollment_id: str, owned_process_handle: Any,
                                operation: str, *, timeout: float = 10.0,
                                cancelled: Callable[[], bool] | None = None) -> Any:
        """Revalidate and perform one same-process status or fixed shutdown.

        This is the production callpoint for controls after the original
        admission lease expires. Every call receives fresh source, choice,
        consent, controller PIDFD and process-identity evidence; it cannot
        launch or extend the retained process deadline.
        """
        if operation not in {"process.status", "process.stop"}:
            raise RootMemoryLifecycleRegistryDenied("only process.status or process.stop is available")
        admission = self.readmit_selected_control(
            memory_enrollment_id, owned_process_handle, operation)
        return self.perform_selected_control(
            admission, owned_process_handle, operation,
            reason="shutdown", timeout=timeout, cancelled=cancelled)

    def status_selected_memory(self, memory_enrollment_id: str,
                               owned_process_handle: Any, *, timeout: float = 10.0,
                               cancelled: Callable[[], bool] | None = None) -> Any:
        return self.control_selected_memory(
            memory_enrollment_id, owned_process_handle, "process.status",
            timeout=timeout, cancelled=cancelled)

    def stop_selected_memory(self, memory_enrollment_id: str,
                             owned_process_handle: Any, *, timeout: float = 10.0,
                             cancelled: Callable[[], bool] | None = None) -> Any:
        return self.control_selected_memory(
            memory_enrollment_id, owned_process_handle, "process.stop",
            timeout=timeout, cancelled=cancelled)

    def resolve_start_receipt(self, receipt_handle: str) -> RootMemoryServiceStartReceipt:
        with self._lock:
            receipt = self._receipts.get(receipt_handle)
        if type(receipt) is not RootMemoryServiceStartReceipt or not receipt.is_current():
            raise RootMemoryLifecycleRegistryDenied("memory service start or readiness receipt is stale")
        return receipt

    def __repr__(self) -> str:
        return "RootMemoryLifecycleRegistry(<root-private>)"
