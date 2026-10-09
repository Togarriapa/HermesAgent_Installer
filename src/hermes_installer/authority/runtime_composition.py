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
    scope_bindings: Mapping[str, Any]
    validators: Mapping[str, Any]
    job_enrollments: Mapping[tuple[str, str], Any]
    memory_runtime: Any | None
    job_authority: Any | None
    build_execution_service: Any | None

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
    def source_observer_enrollments(self) -> Mapping[str, Any]:
        """Typed candidates derived from exact active issuer/package joins.

        These are enrollment metadata, not proof that a package is currently
        loaded or that a receipt may be issued. Registry construction still
        requires the live loader and recipient PIDFD proof resolvers.
        """
        records = getattr(self.bindings, "source_observer_enrollments", {})
        return MappingProxyType(dict(records)) if isinstance(records, Mapping) else MappingProxyType({})

    @property
    def native_runtime_observer(self) -> Any | None:
        return getattr(self.service, "native_runtime_observer", None)

    @property
    def native_loader_observation_store(self) -> Any | None:
        return getattr(self.service, "native_loader_observation_store", None)

    @property
    def remote_session_authority(self) -> Any | None:
        return self.service.remote_session_authority

    def prune(self) -> None:
        """Prune root observer leases using the service's attached registry."""
        registry = self.source_observer_registry
        prune = getattr(registry, "prune", None)
        if callable(prune):
            prune()

    def revoke_native_process(self, process_id: str, generation: str | None = None) -> None:
        """Revoke loader proofs when the root process manager retires a process."""
        store = self.native_loader_observation_store
        revoke = getattr(store, "revoke_process", None)
        if callable(revoke):
            revoke(process_id, generation)

    def close(self) -> None:
        """Close attached root observers and stop the active remote lease worker."""
        for component in (self.native_runtime_observer, self.source_observer_registry,
                          self.native_loader_observation_store):
            close = getattr(component, "close", None)
            if callable(close):
                close()
        directories = (self.memory_runtime.get("state_directories", {})
                       if isinstance(self.memory_runtime, Mapping) else {})
        for directory in directories.values() if isinstance(directories, Mapping) else ():
            close = getattr(directory, "close", None)
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

    def resolve_root_journal(self, root_id: str, *,
                             expected_active_generation_digest: str) -> Any:
        """Resolve a journal only inside this exact active protected snapshot.

        The protected enrollment catalog revalidates its selected root row and
        filesystem identity. This wrapper prevents a caller from asking the
        catalog for a root under a stale or caller-selected generation.
        """
        if (not isinstance(root_id, str) or not root_id
                or expected_active_generation_digest
                != self.enrollment.protected_enrollment_digest):
            raise AuthorityDenied("journal.unavailable", "journal root is outside the active protected generation")
        resolver = getattr(self.bindings, "resolve_root_journal", None)
        if not callable(resolver):
            raise AuthorityDenied("journal.unavailable", "root bindings have no protected journal resolver")
        return resolver(
            root_id,
            expected_active_generation_digest=expected_active_generation_digest,
        )


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
        parse_resource_scope_binding_records, parse_resource_validator_records,
    )

    backends = parse_resource_backend_records(enrollment.resource_backend_enrollment_records)
    recipes = parse_resource_body_recipes(enrollment.resource_body_recipe_records)
    scope_bindings = parse_resource_scope_binding_records(
        getattr(enrollment, "resource_scope_binding_records", ()))
    validators = parse_resource_validator_records(
        getattr(enrollment, "resource_validator_records", ()))
    source_observers = service.source_observer_registry
    observer_records = getattr(source_observers, "observers", MappingProxyType({}))
    issuer_records = {
        record.issuer_channel_id: record for record in enrollment.source_issuers
    }
    jobs = index_resource_job_records(
        enrollment.resource_job_records,
        backend_enrollments=backends,
        body_recipes=recipes,
        scope_bindings=scope_bindings,
        validators=validators,
        source_issuers=issuer_records,
        source_observers=observer_records,
    )

    memory_runtime = None
    if enrollment.memory_enrollments:
        if (bindings.enrollment_catalog is None
                or not callable(getattr(bindings, "resolve_root_journal", None))
                or bindings.process_manager is not service.process_effect_handler):
            raise AuthorityDenied(
                "authority.composition",
                "active memory enrollments require the protected service catalog, journal resolver, and shared process custody",
            )
        from hermes_installer.memory.broker import build_memory_handlers, build_memory_runtime
        from hermes_installer.memory.enrollment import MemoryServiceEnrollment

        memory_targets: dict[tuple[str, str, str], Any] = {}
        by_profile_generation: dict[tuple[str, str], Any] = {}
        for item in enrollment.memory_enrollments.values():
            if not isinstance(item, MemoryServiceEnrollment):
                raise AuthorityDenied("authority.composition", "active memory enrollment is not a typed protected record")
            principal_resolver = getattr(bindings, "resolve_selected_native_principal", None)
            catalog_digest = getattr(bindings.enrollment_catalog, "digest", None)
            if not callable(principal_resolver) or not isinstance(catalog_digest, str):
                raise AuthorityDenied("authority.composition", "active memory principal binding resolver is unavailable")
            try:
                principal = principal_resolver(
                    item.profile_id, item.service_generation, catalog_digest,
                )
            except Exception:
                raise AuthorityDenied("authority.composition", "active memory principal is stale or absent") from None
            if (getattr(principal, "principal_id", None) != item.principal_id
                    or getattr(principal, "profile_id", None) != item.profile_id
                    or getattr(principal, "namespace_id", None) != item.namespace_identity
                    or service.profile_generations.get(item.profile_id) != item.service_generation):
                raise AuthorityDenied("authority.composition", "memory enrollment differs from its selected authority principal")
            target_key = (item.profile_id, item.namespace_identity, item.provider)
            prior_target = memory_targets.get(target_key)
            if prior_target is not None and prior_target != item:
                raise AuthorityDenied("authority.composition", "active memory target enrollment is ambiguous")
            memory_targets[target_key] = item
            profile_key = (item.profile_id, item.service_generation)
            prior_enrollment = by_profile_generation.get(profile_key)
            if prior_enrollment is not None and prior_enrollment != item:
                raise AuthorityDenied("authority.composition", "active memory profile generation resolves ambiguously")
            by_profile_generation[profile_key] = item

        def resolve_memory_enrollment(profile_id: str, generation: str) -> Any:
            selected = by_profile_generation.get((profile_id, generation))
            if selected is None:
                raise AuthorityDenied("memory.unavailable", "memory enrollment is not active in this generation")
            return selected

        memory_runtime = build_memory_runtime(
            memory_targets, service,
            root_journal_resolver=bindings.resolve_root_journal,
            expected_active_generation_digest=enrollment.protected_enrollment_digest,
            vault=vault, service_catalog=bindings.enrollment_catalog,
            process_manager=bindings.process_manager,
            enrollment_resolver=resolve_memory_enrollment,
        )
        if memory_runtime.get("state_root_ready") is True:
            step_authority = memory_runtime.get("step_authority")
            # Derive only fixed handlers whose selected route has a complete
            # protected compound recipe and a corresponding unique HI12 rule.
            # Capture remains unavailable until a root-observed event joins it.
            generated = build_memory_handlers(
                targets=memory_runtime["targets"],
                owner_state=memory_runtime["owner_state"],
                queue=memory_runtime["queue"], ipc=memory_runtime["ipc"],
                engines=memory_runtime["engines"],
                eligibility=memory_runtime["eligibility"],
                maximum_timeout=memory_runtime["maximum_timeout"],
                compound_executor=memory_runtime["compound_executor"],
            )
            for key, handler in generated.items():
                operation, target = key
                if operation != "memory.search":
                    continue
                target_entry = next((value for value in memory_runtime["targets"].values()
                                     if "memory:" + value.provider + ":search" == target), None)
                route_id = target_entry.route_for("search") if target_entry is not None else None
                connector_key = (("connector.open", target_entry.enrollment.target_id)
                                 if target_entry is not None and target_entry.enrollment is not None
                                 else None)
                installed_connector = (service.handlers.get(connector_key)
                                       if connector_key is not None else None)
                internal_handler = (getattr(step_authority, "handle_connector_open", None)
                                    if step_authority is not None else None)
                same_connector = (
                    installed_connector is internal_handler
                    or (getattr(installed_connector, "__self__", None) is step_authority
                        and getattr(installed_connector, "__func__", None)
                        is getattr(internal_handler, "__func__", None))
                )
                if (route_id is None or route_id not in target_entry.enrollment.fixed_route_map
                        or service.memory_step_effect_authority is not step_authority
                        or not same_connector
                        or not callable(internal_handler)
                        or not any(rule.operation == operation and rule.target == target
                                   for rule in service.rules.values())):
                    continue
                if key in service.handlers:
                    raise AuthorityDenied("authority.composition", "active memory route duplicates an installed handler")
                service.handlers[key] = handler

    build_execution_service = None
    build_catalog = getattr(bindings, "build_catalog", None)
    build_store = getattr(bindings, "build_store", None)
    process_manager = bindings.process_manager
    if (build_catalog is not None and build_store is not None
            and bindings.enrollment_catalog is not None
            and isinstance(enrollment.artifact_staging_directory, Path)
            and callable(getattr(bindings, "resolve_build_process_profile", None))):
        # The root store and process manager are the same protected instances
        # already held by RootRuntimeBindings; no second store, key, or manager
        # is created here. Without a root CPython probe, handlers() exposes
        # Colibri only and leaves Coral unavailable.
        from .build_execution import (
            LinuxBuildOutputFactInspector, ProtectedBuildArtifactRootResolver,
            RootBuildExecutionService,
        )
        from hermes_installer.managed_process_custodian import ManagedBuildJobRunner

        artifact_roots = ProtectedBuildArtifactRootResolver(
            artifact_catalog, enrollment.artifact_staging_directory,
            owner_uid=vault.expected_uid,
        )
        inspector = LinuxBuildOutputFactInspector(
            toolchain_root_resolver=artifact_roots.toolchain_root,
            source_root_resolver=artifact_roots.source_root,
            runtime_probe=None,
            owner_uid=vault.expected_uid,
        )
        candidate_build_execution_service = RootBuildExecutionService(
            build_catalog=build_catalog,
            service_catalog=bindings.enrollment_catalog,
            artifact_catalog=artifact_catalog,
            artifact_staging_root=enrollment.artifact_staging_directory,
            launcher=ManagedBuildJobRunner(
                process_manager,
                process_profile_resolver=bindings.resolve_build_process_profile,
            ),
            fact_inspector=inspector,
            store=build_store,
            expected_uid=vault.expected_uid,
            monotonic=service.monotonic,
        )
        installed_build_routes = 0
        for key, handler in candidate_build_execution_service.handlers().items():
            operation, target = key
            # A catalog profile alone is not activation. Install only if the
            # active service snapshot also grants this exact selected route.
            selected = False
            if not any(rule.operation == operation and rule.target == target
                       for rule in service.rules.values()):
                continue
            for protected_build_row in enrollment.protected_build_records:
                if not isinstance(protected_build_row, Mapping):
                    continue
                generation = protected_build_row.get("generation")
                if (protected_build_row.get("target_id") != target
                        or not isinstance(generation, str) or not generation):
                    continue
                try:
                    profile = build_catalog.resolve(target, generation)
                    service_profile = bindings.enrollment_catalog.resolve(
                        profile.build_service_enrollment_id,
                        profile.build_service_generation,
                    )
                except Exception:
                    continue
                if (service_profile.profile_id in service.profile_generations
                        and service.profile_generations[service_profile.profile_id]
                        == service_profile.generation):
                    selected = True
                    break
            if not selected:
                continue
            if key in service.handlers:
                raise AuthorityDenied("authority.composition", "build route duplicates an installed handler")
            service.handlers[key] = handler
            installed_build_routes += 1
        if installed_build_routes:
            build_execution_service = candidate_build_execution_service

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
        scope_bindings=MappingProxyType(dict(scope_bindings)),
        validators=MappingProxyType(dict(validators)),
        job_enrollments=MappingProxyType(dict(jobs)), memory_runtime=memory_runtime,
        job_authority=job_authority, build_execution_service=build_execution_service,
    )
