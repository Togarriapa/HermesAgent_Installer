"""Production construction of the root Resources controller-role runtime.

Only active protected enrollment, the installed release closure, and the
systemd MainPID can install dispatcher role code.  The runtime owns all loaded
role modules and revokes them as one service-generation epoch.
"""
from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from hermes_installer.artifacts import ArtifactCatalog
from hermes_installer.authority.enrollment import ProtectedEnrollment, SourceIssuerRecord
from hermes_installer.authority.installer_release import (
    RootActorObservation, VerifiedInstallerReleaseReceipt,
)
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.authority.service import AuthorityService
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.registry.resource_jobs import ResourceJobEnrollment
from hermes_installer.registry.resources_runtime import SelectedResourceRegistry

from .root_controller_custody import (
    ControllerExecutablePin,
    RootControllerEventBinding,
    RootControllerRoleCatalog,
    RootControllerRoleModuleRegistry,
    RootControllerRoleResolver,
    RootSelectedIngressBinding,
    SystemdMainPidInspector,
)


class RootSelectedIngressBindingResolver:
    """Resolve the exact active role/issuer/backend/source registration tuple."""

    def __init__(self, *, service: AuthorityService, catalog: RootControllerRoleCatalog,
                 issuers: tuple[SourceIssuerRecord, ...],
                 source_observers: Any,
                 job_enrollments: Mapping[tuple[str, str], ResourceJobEnrollment],
                 selected_resources: SelectedResourceRegistry,
                 monotonic=time.monotonic):
        if (not isinstance(service, AuthorityService)
                or not isinstance(catalog, RootControllerRoleCatalog)
                or not isinstance(selected_resources, SelectedResourceRegistry)
                or not isinstance(job_enrollments, Mapping)
                or not isinstance(issuers, tuple)
                or any(not isinstance(row, SourceIssuerRecord) for row in issuers)
                or not isinstance(getattr(source_observers, "observers", None), Mapping)
                or not callable(monotonic)):
            raise AuthorityDenied("controller.ingress", "typed selected ingress catalogs are required")
        self._service, self._catalog = service, catalog
        self._issuers = MappingProxyType({row.issuer_channel_id: row for row in issuers})
        if len(self._issuers) != len(issuers):
            raise AuthorityDenied("controller.ingress", "source issuer IDs are ambiguous")
        self._source_observers = source_observers
        self._jobs = MappingProxyType(dict(job_enrollments))
        self._selected_resources = selected_resources
        self._monotonic = monotonic

    def __call__(self, role_id: str, issuer_id: str, backend_id: str) -> RootSelectedIngressBinding:
        if (self._service.service_generation_digest != self._catalog.generation_digest
                or not self._service.authority_epoch):
            raise AuthorityDenied("controller.generation", "selected ingress generation is stale")
        role = self._catalog.get(role_id)
        issuer = self._issuers.get(issuer_id)
        if issuer is None:
            raise AuthorityDenied("controller.issuer", "selected source issuer is absent")
        matches = [job for job in self._jobs.values()
                   if isinstance(job, ResourceJobEnrollment)
                   and job.selected_enabled is True
                   and job.source_issuer_channel_id == issuer_id
                   and backend_id in job.backends]
        if len(matches) != 1:
            raise AuthorityDenied("controller.ingress", "selected job/backend is missing or ambiguous")
        job = matches[0]
        backend = job.backends[backend_id]
        source_kind = {"crons": "schedule-event", "webhooks": "webhook-event",
                       "channels": "native-input"}.get(job.kind)
        controller_kind = {"crons": "root-scheduler", "webhooks": "root-webhook",
                           "channels": "root-channel"}.get(job.kind)
        observer = self._source_observers.observers.get(job.observer_enrollment_id)
        selected = [row for row in self._selected_resources.rows
                    if row.identity.kind == job.kind
                    and row.identity.resource_id == job.resource_id
                    and row.generation_digest == job.generation
                    and row.profile_id == job.profile_id and row.enabled is True]
        if (len(selected) != 1 or observer is None or role.controller_kind != controller_kind
                or observer.source_kind != source_kind
                or issuer.observer_enrollment_id != job.observer_enrollment_id
                or issuer.generation != job.profile_generation
                or issuer.producer_profile_id != job.profile_id
                or observer.observer_enrollment_id not in role.source_observer_enrollment_ids
                or observer.source_kind != source_kind
                or observer.profile_id != job.profile_id
                or observer.principal_id != job.principal_id
                or observer.generation != job.profile_generation
                or observer.channel_id != issuer_id
                or backend.backend_id != backend_id
                or backend.resource_id != job.resource_id
                or backend.generation != job.generation
                or backend.profile_id != job.profile_id
                or backend.profile_generation != job.profile_generation
                or backend.principal_id != job.principal_id
                or backend.source_issuer_channel_id != issuer_id
                or backend.observer_enrollment_id != observer.observer_enrollment_id
                or backend_id not in role.allowed_backend_enrollment_ids
                or backend.operation not in role.allowed_operations
                or issuer.capture_schema_id != observer.capture_schema_id
                or not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,256}", job.schedule_or_route_id)):
            raise AuthorityDenied("controller.join", "selected role/issuer/resource/backend/source join failed")
        # schedule_or_route_id is the active protected source registration key
        # from the selected resource-job row (timer, route, or channel route).
        # It is static selection metadata, never an event or receipt identifier.
        return RootSelectedIngressBinding(
            role=role, source_issuer=issuer, source_observer=observer, backend=backend,
            resource_generation=job.generation,
            service_generation_digest=self._catalog.generation_digest,
            authority_epoch=self._service.authority_epoch,
            selected_ingress_binding_id=job.schedule_or_route_id,
            expires_monotonic=self._monotonic() + role.max_lease_seconds,
        )


class RootControllerEventBindingDirectory:
    """One-time typed seam from role custody to the assembled event registry."""

    def __init__(self, service: AuthorityService, catalog: RootControllerRoleCatalog):
        self._service, self._catalog = service, catalog
        self._registry: Any | None = None
        self._lock = threading.RLock()

    def attach(self, registry: Any) -> None:
        from .resource_source_controllers import RootResourceControllerRegistry
        if (not isinstance(registry, RootResourceControllerRegistry)
                or registry.service is not self._service
                or registry.service_generation_digest != self._catalog.generation_digest):
            raise AuthorityDenied("controller.event", "active root event registry does not match this epoch")
        with self._lock:
            if self._registry is not None:
                raise AuthorityDenied("controller.event", "root event registry is already attached")
            self._registry = registry

    def detach(self) -> None:
        with self._lock:
            self._registry = None

    def __call__(self, event_handle: str, node_id: str) -> RootControllerEventBinding:
        with self._lock:
            registry = self._registry
        if registry is None or self._service.service_generation_digest != self._catalog.generation_digest:
            raise AuthorityDenied("controller.event", "current root event registry is unavailable")
        binding = registry.controller_binding_for_event(event_handle, node_id)
        if (not isinstance(binding, RootControllerEventBinding)
                or binding.service_generation_digest != self._catalog.generation_digest
                or binding.authority_epoch != self._service.authority_epoch):
            raise AuthorityDenied("controller.event", "event binding does not match active role epoch")
        return binding


@dataclass(slots=True)
class RootControllerRoleRuntime:
    """Owned module registry/resolver for one live root service generation."""

    service: AuthorityService
    resolver: RootControllerRoleResolver
    loaded_role_registry: RootControllerRoleModuleRegistry
    catalog: RootControllerRoleCatalog
    event_bindings: RootControllerEventBindingDirectory
    selected_ingress_bindings: RootSelectedIngressBindingResolver
    _closed: bool = False

    @classmethod
    def from_root_runtime(
        cls, *, service: AuthorityService, enrollment: ProtectedEnrollment,
        bindings: RootRuntimeBindings,
        release_receipt: VerifiedInstallerReleaseReceipt,
        actor_observation: RootActorObservation,
        inspector: SystemdMainPidInspector,
        job_enrollments: Mapping[tuple[str, str], ResourceJobEnrollment],
        selected_resources: SelectedResourceRegistry,
        source_observers: Any,
        monotonic=time.monotonic,
    ) -> "RootControllerRoleRuntime":
        """Build production custody from active enrollment and installed code.

        This must run in the selected root systemd MainPID after installed
        release actor verification. The source observer/event registry is
        attached once it is assembled; there is no caller-supplied PID,
        boolean, module bytes, executable path, or arbitrary selected row.
        """
        if (not isinstance(service, AuthorityService)
                or not isinstance(enrollment, ProtectedEnrollment)
                or not isinstance(bindings, RootRuntimeBindings)
                or not isinstance(bindings.artifact_catalog, ArtifactCatalog)
                or not isinstance(release_receipt, VerifiedInstallerReleaseReceipt)
                or not isinstance(actor_observation, RootActorObservation)
                or not isinstance(inspector, SystemdMainPidInspector)
                or not isinstance(selected_resources, SelectedResourceRegistry)
                or not isinstance(job_enrollments, Mapping)
                or service.service_generation_digest != enrollment.protected_enrollment_digest
                or service.service_generation_digest != bindings.enrollment_catalog.digest
                or not isinstance(bindings.resource_controller_role_records, tuple)
                or not bindings.resource_controller_role_records):
            raise AuthorityDenied("controller.runtime", "active root role runtime inputs are unavailable")
        if actor_observation.pid != os.getpid() or os.geteuid() != 0:
            raise AuthorityDenied("controller.runtime", "runtime is not the verified root service actor")
        try:
            actor_observation.verify_current(release_receipt)
            catalog = RootControllerRoleCatalog(
                bindings.resource_controller_role_records,
                generation_digest=service.service_generation_digest,
            )
            # Resolve every executable pin through the active ArtifactCatalog
            # and protected staging root before asking systemd for MainPID.
            pins: dict[str, ControllerExecutablePin] = {}
            identities = {}
            for role in catalog.rows:
                resolved = bindings.artifact_catalog.resolve(
                    role.daemon_executable_artifact_id, role.daemon_executable_sha256,
                    enrollment.artifact_staging_directory, expected_uid=0,
                )
                pin = ControllerExecutablePin(
                    artifact_id=resolved.artifact_id, path=resolved.path, sha256=resolved.sha256,
                )
                pins[role.daemon_executable_artifact_id] = pin
                identity = inspector.inspect(role.daemon_unit_id, pin)
                try:
                    if (identity.pid != os.getpid() or identity.uid != 0
                            or identity.daemon_unit_id != role.daemon_unit_id
                            or identity.executable_artifact_id != role.daemon_executable_artifact_id
                            or identity.executable_sha256 != role.daemon_executable_sha256
                            or not inspector.is_pidfd_live(identity.pidfd, identity.pid)):
                        raise AuthorityDenied("controller.identity", "selected root systemd MainPID differs from this actor")
                    identities[(role.daemon_unit_id, identity.pid)] = identity
                finally:
                    inspector.close_pidfd(identity.pidfd)
            module_registry = RootControllerRoleModuleRegistry()
            for role in catalog.rows:
                member = next((item for item in release_receipt.files
                               if item.artifact_id == role.role_module_artifact_id), None)
                if member is None:
                    raise AuthorityDenied("controller.module", "selected role module is absent from installed release")
                module_name = "_hermes_root_role_" + hashlib.sha256(
                    (role.id + ":" + role.controller_generation + ":" + role.role_module_sha256).encode()
                ).hexdigest()
                module_registry.load_from_installed_release(
                    release_receipt=release_receipt, module_name=module_name,
                    artifact_id=role.role_module_artifact_id,
                    expected_sha256=role.role_module_sha256,
                    service_generation_digest=service.service_generation_digest,
                    controller_generation=role.controller_generation,
                )
            event_directory = RootControllerEventBindingDirectory(service, catalog)
            selected_resolver = RootSelectedIngressBindingResolver(
                service=service, catalog=catalog,
                issuers=tuple(bindings.enrollment_catalog.source_issuers),
                source_observers=source_observers,
                job_enrollments=job_enrollments,
                selected_resources=selected_resources,
                monotonic=monotonic,
            )
            resolver = RootControllerRoleResolver(
                catalog=catalog,
                event_binding_resolver=event_directory,
                inspector=inspector,
                executable_resolver=lambda artifact_id: pins[artifact_id],
                loaded_role_registry=module_registry,
                current_generation_digest=lambda: service.service_generation_digest,
                selected_ingress_binding_resolver=selected_resolver,
                monotonic=monotonic,
            )
            release_receipt.verify_current()
            actor_observation.verify_current(release_receipt)
            return cls(service, resolver, module_registry, catalog, event_directory, selected_resolver)
        except AuthorityDenied:
            if "module_registry" in locals():
                module_registry.revoke_generation(service.service_generation_digest)
            raise
        except Exception:
            if "module_registry" in locals():
                module_registry.revoke_generation(service.service_generation_digest)
            raise AuthorityDenied("controller.runtime", "root controller runtime composition failed closed") from None

    def attach_event_registry(self, registry: Any) -> None:
        if self._closed:
            raise AuthorityDenied("controller.runtime", "root controller runtime is closed")
        self.event_bindings.attach(registry)

    def resolve_selected_ingress_controller(self, role_id: str, issuer_id: str,
                                            backend_id: str) -> Any:
        if self._closed:
            raise AuthorityDenied("controller.runtime", "root controller runtime is closed")
        return self.resolver.resolve_selected_ingress_controller(role_id, issuer_id, backend_id)

    def resolve_selected_ingress_binding(self, role_id: str, issuer_id: str,
                                         backend_id: str) -> RootSelectedIngressBinding:
        """Return the current protected static binding before event capture."""
        if self._closed:
            raise AuthorityDenied("controller.runtime", "root controller runtime is closed")
        binding = self.selected_ingress_bindings(role_id, issuer_id, backend_id)
        RootControllerRoleResolver._ingress_join(binding, role_id, issuer_id, backend_id)
        if (self.resolver._current_generation_digest() != self.catalog.generation_digest
                or binding.service_generation_digest != self.catalog.generation_digest
                or self.service.authority_epoch != binding.authority_epoch
                or binding.expires_monotonic <= self.resolver._monotonic()):
            raise AuthorityDenied("controller.ingress", "selected static ingress binding is stale")
        return binding

    def release_ingress_proof(self, proof_handle: str) -> None:
        if self._closed:
            return
        self.resolver.release_ingress_proof(proof_handle)

    def resolve_for_event(self, root_event_handle: str, node_id: str) -> Any:
        if self._closed:
            raise AuthorityDenied("controller.runtime", "root controller runtime is closed")
        return self.resolver.resolve_for_event(root_event_handle, node_id)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.event_bindings.detach()
        self.resolver.revoke_generation(self.catalog.generation_digest)
        self.loaded_role_registry.revoke_generation(self.catalog.generation_digest)
