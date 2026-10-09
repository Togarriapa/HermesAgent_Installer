"""Join the protected active catalogs to concrete root authority components.

This module runs after the root enrollment loader and ``RootRuntimeBindings``
builder. It accepts those verified objects, never caller-selected factories,
capability flags, or paths from a worker. Components are returned as one
immutable epoch-scoped object so the daemon can install the exact instances it
serves and close them together at shutdown.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from hermes_installer.artifacts import ArtifactCatalog
from hermes_installer.authority.service import AuthorityService
from hermes_installer.authority.enrollment import ProtectedEnrollment, RootCredentialVault
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.authority.types import AuthorityDenied


@dataclass(frozen=True, slots=True)
class RootAuthorityRuntime:
    """Concrete root-owned catalog joins for one AuthorityService epoch."""

    service: AuthorityService
    enrollment: ProtectedEnrollment
    bindings: RootRuntimeBindings
    artifact_catalog: ArtifactCatalog
    vault: RootCredentialVault
    boot_epoch: str
    backend_enrollments: Mapping[str, Any]
    body_recipes: Mapping[str, Any]
    job_enrollments: Mapping[tuple[str, str], Any]
    job_authority: Any | None

    @property
    def process_manager(self) -> Any:
        return self.bindings.process_manager

    @property
    def service_connector(self) -> Any:
        return self.bindings.service_connector

    @property
    def build_catalog(self) -> Any:
        return self.bindings.build_catalog

    @property
    def device_catalog(self) -> Any:
        return self.bindings.device_catalog

    @property
    def remote_session_enrollments(self) -> Mapping[str, Any]:
        return self.bindings.remote_session_enrollments

    @property
    def source_observer_registry(self) -> Any | None:
        return self.service.source_observer_registry

    @property
    def native_runtime_observer(self) -> Any | None:
        return getattr(self.service, "native_runtime_observer", None)

    @property
    def remote_session_authority(self) -> Any | None:
        return self.service.remote_session_authority

    def prune(self) -> None:
        """Prune root observer leases using the service's attached registry."""
        registry = self.source_observer_registry
        prune = getattr(registry, "prune", None)
        if callable(prune):
            prune()

    def close(self) -> None:
        """Close attached root observers and stop the active remote lease worker."""
        for component in (self.native_runtime_observer, self.source_observer_registry):
            close = getattr(component, "close", None)
            if callable(close):
                close()
        stop = getattr(self.remote_session_authority, "stop_watchdog", None)
        if callable(stop):
            stop()

    def resolve_native_package(self, package_id: str, generation: str) -> Any:
        return self.bindings.resolve_native_package(package_id, generation)

    def resolve_selected_native_principal(
        self, profile_id: str, generation: str, service_generation_digest: str,
    ) -> Any:
        return self.bindings.resolve_selected_native_principal(
            profile_id, generation, service_generation_digest,
        )

    def resolve_device(self, enrollment_id: str, generation: str) -> Any:
        return self.bindings.resolve_device(enrollment_id, generation)

    def resolve_operation(self, enrollment_id: str, generation: str,
                          operation: str, operation_id: str) -> Any:
        return self.bindings.resolve_selected_operation(
            enrollment_id, generation, operation, operation_id,
        )

    def resolve_artifact_store_id(self, store_id: str) -> Any:
        resolver = getattr(self.artifact_catalog, "resolve_store_id", None)
        if not callable(resolver):
            raise AuthorityDenied("artifact.unavailable", "root artifact catalog has no protected store resolver")
        return resolver(store_id, self.enrollment.artifact_staging_directory,
                        expected_uid=self.vault.expected_uid)

    def resolve_live_peer(self, peer_pid: int, peer_pidfd: int, *,
                          profile_id: str, generation: str) -> Any:
        resolver = getattr(self.process_manager, "resolve_live_peer", None)
        if not callable(resolver):
            raise AuthorityDenied("process.unavailable", "root process custody has no live peer resolver")
        return resolver(peer_pid, peer_pidfd, profile_id=profile_id, generation=generation)

    def resolve_loaded_native_package(self, process_id: str, generation: str) -> Any:
        resolver = getattr(self.process_manager, "resolve_loaded_native_package", None)
        if not callable(resolver):
            raise AuthorityDenied("native.unavailable", "root process custody has no loaded package resolver")
        return resolver(process_id, generation)


def compose_root_authority_runtime(
    *,
    service: AuthorityService,
    enrollment: ProtectedEnrollment,
    bindings: RootRuntimeBindings,
    artifact_catalog: ArtifactCatalog,
    vault: RootCredentialVault,
    resource_job_store: Path | None = None,
) -> RootAuthorityRuntime:
    """Assemble selected runtime registries from the active verified snapshot.

    The optional job store is a concrete filesystem location supplied by the
    root daemon's fixed service configuration. If active resource jobs exist,
    the root-installed SourceObserverRegistry must already be attached to the
    real service; missing observer, artifact, backend, or effect joins leave
    individual jobs unregistered.
    """
    if (not isinstance(service, AuthorityService)
            or not isinstance(enrollment, ProtectedEnrollment)
            or not isinstance(bindings, RootRuntimeBindings)
            or not isinstance(artifact_catalog, ArtifactCatalog)
            or not isinstance(vault, RootCredentialVault)):
        raise AuthorityDenied("authority.composition", "root runtime inputs are not verified authority objects")
    if (bindings.artifact_catalog is not artifact_catalog
            or bindings.process_manager is not service.process_effect_handler
            or not isinstance(service.authority_epoch, str) or not service.authority_epoch
            or service.service_generation_digest != enrollment.protected_enrollment_digest):
        raise AuthorityDenied("authority.composition", "runtime bindings do not match this service epoch and catalog")

    from .resource_jobs import (
        ResourceJobAuthority, index_resource_job_records,
        parse_resource_backend_records, parse_resource_body_recipes,
    )

    backends = parse_resource_backend_records(enrollment.resource_backend_enrollment_records)
    recipes = parse_resource_body_recipes(enrollment.resource_body_recipe_records)
    source_observers = service.source_observer_registry
    observer_records = getattr(source_observers, "observers", MappingProxyType({}))
    issuer_records = {
        record.issuer_channel_id: record for record in enrollment.source_issuers
    }
    jobs = index_resource_job_records(
        enrollment.resource_job_records,
        backend_enrollments=backends,
        body_recipes=recipes,
        source_issuers=issuer_records,
        source_observers=observer_records,
    )

    job_authority = None
    if jobs:
        if not isinstance(resource_job_store, Path) or not resource_job_store.is_absolute():
            raise AuthorityDenied("authority.composition", "active resource jobs require a fixed private root store")
        if source_observers is None:
            raise AuthorityDenied("authority.composition", "active resource jobs have no root source observer")
        from hermes_installer.registry.resource_jobs import ResourceJobLedger

        ledger = ResourceJobLedger(resource_job_store, monotonic=service.monotonic)
        selected_generations: dict[str, str] = {}
        for row in enrollment.resource_job_records:
            if row.get("selected_enabled") is True:
                resource_id, generation = row.get("resource_id"), row.get("generation")
                if isinstance(resource_id, str) and isinstance(generation, str):
                    old = selected_generations.setdefault(resource_id, generation)
                    if old != generation:
                        raise AuthorityDenied("authority.composition", "active resource generations are ambiguous")

        def selected_generation(resource_id: str) -> str:
            generation = selected_generations.get(resource_id)
            if generation is None:
                raise AuthorityDenied("resource.unavailable", "resource is not selected in the active generation")
            return generation

        job_authority = ResourceJobAuthority(
            service=service, enrollments=jobs, ledger=ledger,
            selected_generation=selected_generation,
        )
        job_handlers = job_authority.handlers()
        for key in job_handlers:
            if key in service.handlers:
                raise AuthorityDenied("authority.composition", "resource job route duplicates an active handler")
            if not any(rule.operation == key[0] and rule.target == key[1]
                       for rule in service.rules.values()):
                raise AuthorityDenied("authority.composition", "resource job route lacks a protected effect rule")
        service.handlers.update(job_handlers)

    return RootAuthorityRuntime(
        service=service, enrollment=enrollment, bindings=bindings,
        artifact_catalog=artifact_catalog, vault=vault,
        boot_epoch=service.authority_epoch,
        backend_enrollments=MappingProxyType(dict(backends)),
        body_recipes=MappingProxyType(dict(recipes)),
        job_enrollments=MappingProxyType(dict(jobs)), job_authority=job_authority,
    )
