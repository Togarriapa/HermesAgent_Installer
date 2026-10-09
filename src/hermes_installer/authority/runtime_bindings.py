"""Composition of verified root enrollment into fixed authority handlers.

This module is deliberately downstream of the authority file verifier. It does
not parse caller data, choose a path, or accept worker supplied factories.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping

from hermes_installer.protected_enrollment import (
    EnrollmentDenied,
    ProtectedBuildCatalog,
    ProtectedDeviceCatalog,
    ProtectedEnrollmentCatalog,
)


@dataclass(frozen=True, slots=True)
class SelectedProcessOperation:
    operation: str
    operation_id: str
    target: str
    enrollment_id: str
    generation: str
    profile_id: str
    principal_id: str
    service_uid: int
    service_gid: int


@dataclass(frozen=True, slots=True)
class RootRuntimeBindings:
    """The immutable handler registrations and selectors for one daemon load."""

    enrollment_catalog: ProtectedEnrollmentCatalog
    build_catalog: ProtectedBuildCatalog
    device_catalog: ProtectedDeviceCatalog
    process_manager: Any
    effect_handlers: Mapping[tuple[str, str], Any]
    native_bridges: Mapping[str, Any]
    artifact_catalog: Any
    build_store: Any
    service_connector: Any

    def resolve_selected_operation(self, enrollment_id: str, generation: str,
                                   operation: str, operation_id: str) -> Any:
        """Join a fixed effect target to one protected typed launch recipe."""
        if operation != "process.start":
            raise EnrollmentDenied("only protected process.start recipes are selectable")
        recipe = self.enrollment_catalog.resolve_launch_recipe(
            enrollment_id, generation, operation_id,
        )
        effect = self.enrollment_catalog.resolve_operation(enrollment_id, generation, operation)
        if (recipe.process_start_target != effect.target
                or recipe.enrollment_id != effect.enrollment_id
                or recipe.generation != effect.generation
                or recipe.profile_id != effect.profile_id
                or recipe.principal_id != effect.principal_id
                or recipe.service_uid != effect.service_uid):
            raise EnrollmentDenied("selected launch recipe and process.start target do not join")
        return SelectedProcessOperation(
            operation=operation, operation_id=recipe.operation_id,
            target=effect.target, enrollment_id=recipe.enrollment_id,
            generation=recipe.generation, profile_id=recipe.profile_id,
            principal_id=recipe.principal_id, service_uid=recipe.service_uid,
            service_gid=recipe.service_gid,
        )

    def resolve_native_package(self, package_id: str, generation: str) -> Any:
        package = self.enrollment_catalog.resolve_native_package(package_id, generation)
        pins = [(package.compiled_closure_artifact_id, package.compiled_closure_sha256),
                (package.entrypoint_artifact_id, package.entrypoint_sha256),
                (package.resolver_artifact_id, package.resolver_sha256)]
        pins.extend((adapter.adapter_artifact_id, adapter.adapter_sha256)
                    for adapter in package.adapter_records.values())
        for artifact_id, digest in pins:
            spec = self.artifact_catalog.artifacts.get(artifact_id)
            if spec is None or spec.sha256 != digest:
                raise EnrollmentDenied("native package artifact pin is absent from protected catalog")
        return package

    def resolve_device(self, enrollment_id: str, generation: str) -> Any:
        return self.enrollment_catalog.resolve_device(
            enrollment_id, generation, self.device_catalog,
        )


def build_root_runtime_bindings(
    enrollment: Any,
    *,
    vault: Any,
    artifact_catalog: Any,
    authorization_check: Callable[..., bool],
    signing_key: bytes | None = None,
    process_handler_options: Mapping[str, Any] | None = None,
    expected_uid: int = 0,
) -> RootRuntimeBindings:
    """Build root handlers only from service-generation records already verified.

    `enrollment` is the object returned by the root authority loader. The loader
    must expose `service_records`, `protected_devices`,
    `protected_build_records`, and `protected_enrollment_digest`, all covered by
    its protected file verification. Missing joins fail closed. This makes the
    daemon callsite small while keeping raw configuration parsing in one owner.
    """
    if type(expected_uid) is not int or expected_uid != 0:
        raise EnrollmentDenied("root runtime bindings require the root identity")
    required_attributes = (
        "service_records", "protected_devices",
        "protected_build_records", "protected_enrollment_digest",
    )
    if any(not hasattr(enrollment, name) for name in required_attributes):
        raise EnrollmentDenied("verified generation, device, and build records are unavailable")
    records = enrollment.service_records
    devices = enrollment.protected_devices
    builds = enrollment.protected_build_records
    digest = enrollment.protected_enrollment_digest
    if not isinstance(records, list) or not records:
        raise EnrollmentDenied("protected service generation records are required")
    if not isinstance(devices, list) or not isinstance(builds, list):
        raise EnrollmentDenied("protected hardware catalog records are malformed")

    service_catalog = ProtectedEnrollmentCatalog.from_verified_records(
        records, protected_digest=digest, expected_uid=expected_uid,
        native_packages=getattr(enrollment, "native_package_records", None),
        memory_enrollments=getattr(enrollment, "memory_enrollments", None),
        parameter_schemas=getattr(enrollment, "operation_parameter_schemas", None),
    )
    build_catalog = ProtectedBuildCatalog.from_protected_records(builds)
    device_catalog = ProtectedDeviceCatalog.from_protected_records(devices)

    process_profiles = {}
    profile_to_principal = {
        binding.profile_id: (uid, binding)
        for uid, binding in enrollment.bindings_by_uid.items()
    }
    for raw in records:
        profile = service_catalog.resolve(raw["enrollment_id"], raw["generation"])
        principal = profile_to_principal.get(profile.profile_id)
        if principal is None:
            raise EnrollmentDenied("service generation has no protected authority principal")
        uid, binding = principal
        if (uid != profile.service_uid or binding.principal_id != profile.principal_id
                or binding.profile_id != profile.profile_id
                or binding.namespace_id != profile.namespace_identity
                or profile.profile_id in process_profiles):
            raise EnrollmentDenied("service generation identity does not match its authority principal")
        for operation, target in profile.operation_targets.items():
            if not any(
                rule.operation == operation and rule.target == target
                and rule.capability in binding.capabilities
                for rule in enrollment.rules.values()
            ):
                raise EnrollmentDenied("service operation target lacks an exact authority rule")
        for recipe in profile.operation_recipes.values():
            if recipe.parameter_schema_id not in service_catalog.parameter_schemas:
                raise EnrollmentDenied("operation recipe parameter schema is absent from protected catalog")
        # Every child executable is selected by immutable artifact identity and
        # digest from the root-loaded artifact catalog; the worker supplies none.
        child_refs: dict[str, str] = {}
        for artifact_id in profile.runtime_artifact_ids:
            spec = artifact_catalog.artifacts.get(artifact_id)
            if spec is None:
                raise EnrollmentDenied("service runtime artifact is absent from the protected artifact catalog")
            child_refs[f"artifact:{artifact_id}:{spec.sha256}"] = spec.sha256
        for recipe in profile.operation_recipes.values():
            executable_spec = artifact_catalog.artifacts.get(recipe.executable_artifact_id)
            if executable_spec is None or executable_spec.sha256 != recipe.executable_sha256:
                raise EnrollmentDenied("operation executable pin differs from the protected artifact catalog")
            for artifact_id, digest_value in recipe.child_artifact_refs.items():
                child_spec = artifact_catalog.artifacts.get(artifact_id)
                if child_spec is None or child_spec.sha256 != digest_value:
                    raise EnrollmentDenied("operation child artifact pin differs from the protected catalog")
        process_profiles[profile.profile_id] = profile.as_managed_profile(
            artifact_root=enrollment.artifact_staging_directory,
            child_artifact_refs=child_refs,
            parameter_schemas=service_catalog.parameter_schemas,
        )
    if set(process_profiles) != set(profile_to_principal):
        raise EnrollmentDenied("authority process profiles and protected service generations differ")

    from hermes_installer.managed_process_custodian import create_managed_process_handler
    manager_options = dict(process_handler_options or {})
    if "artifact_resolver" in manager_options:
        raise EnrollmentDenied("artifact resolver is fixed by the verified root catalog")
    manager_options["artifact_resolver"] = lambda store_id, sha256: artifact_catalog.resolve_store_id(
        store_id, enrollment.artifact_staging_directory, expected_uid=expected_uid,
    )
    process_manager = create_managed_process_handler(process_profiles, **manager_options)

    from hermes_installer.artifacts import build_artifact_handlers
    artifact_handlers = dict(build_artifact_handlers(
        artifact_catalog, enrollment.artifact_staging_directory,
        expected_uid=expected_uid, authorization_check=authorization_check,
    ))
    effect_handlers = {key: handler for key, handler in artifact_handlers.items()
                       if key[0] == "artifact.fetch"}

    # Generic wheel/environment installation does not bind a selected Coral
    # source-build output. Use only the signed package-set API and resolve its
    # runtime from the same immutable service-generation/build catalogs.
    if signing_key is None:
        from .enrollment import read_protected_file, AUTHORITY_KEY_PATH
        signing_key = read_protected_file(AUTHORITY_KEY_PATH, expected_uid=expected_uid, maximum=64)
    if not isinstance(signing_key, bytes) or len(signing_key) != 32:
        raise EnrollmentDenied("root package-set signing key is unavailable")
    from .build_execution import ContentAddressedBuildStore
    build_store = ContentAddressedBuildStore.root_store(authority_key=signing_key)
    from hermes_installer.artifacts import (
        build_package_set_handlers, load_protected_package_sets,
    )
    package_sets = load_protected_package_sets(
        catalog=artifact_catalog, signing_key=signing_key,
        key_id=enrollment.key_id, expected_uid=expected_uid,
    )
    for package_set_id, spec in package_sets.items():
        profile = service_catalog.resolve(spec.enrollment_id, spec.generation)
        if package_set_id not in profile.package_runtime_records:
            raise EnrollmentDenied("signed package set has no matching protected service runtime record")
        target = f"package-set:{package_set_id}:{spec.manifest_sha256}"
        if not any(getattr(rule, "operation", None) == "package.install"
                   and getattr(rule, "target", None) == target
                   for rule in enrollment.rules.values()):
            raise EnrollmentDenied("signed package set has no exact package.install authority rule")
    effect_handlers.update(build_package_set_handlers(
        artifact_catalog, enrollment.artifact_staging_directory, package_sets,
        runtime_resolver=lambda spec: service_catalog.resolve_package_runtime(
            spec.enrollment_id, spec.generation, spec.package_set_id, build_catalog,
            build_store=build_store,
        ),
        expected_uid=expected_uid, authorization_check=authorization_check,
    ))

    from hermes_installer.service_connector import build_enrolled_service_connector_handlers
    service_connector, connector_handlers = build_enrolled_service_connector_handlers(
        catalog=service_catalog, process_manager=process_manager,
    )
    for key, handler in connector_handlers.items():
        if key in effect_handlers:
            raise EnrollmentDenied("fixed service connector handler conflicts with an existing root handler")
        effect_handlers[key] = handler

    return RootRuntimeBindings(
        enrollment_catalog=service_catalog,
        build_catalog=build_catalog,
        device_catalog=device_catalog,
        process_manager=process_manager,
        effect_handlers=MappingProxyType(effect_handlers),
        native_bridges=MappingProxyType(dict(enrollment.native_bridges)),
        artifact_catalog=artifact_catalog,
        build_store=build_store,
        service_connector=service_connector,
    )
