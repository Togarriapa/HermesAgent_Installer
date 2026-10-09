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
class RootRuntimeBindings:
    """The immutable handler registrations and selectors for one daemon load."""

    enrollment_catalog: ProtectedEnrollmentCatalog
    build_catalog: ProtectedBuildCatalog
    device_catalog: ProtectedDeviceCatalog
    process_manager: Any
    effect_handlers: Mapping[tuple[str, str], Any]
    native_bridges: Mapping[str, Any]

    def resolve_native_package(self, package_id: str, generation: str) -> Any:
        return self.enrollment_catalog.resolve_native_package(package_id, generation)


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
    if not isinstance(records, list) or not records or not isinstance(devices, list) or not devices:
        raise EnrollmentDenied("protected service and exact Coral device records are required")
    if not isinstance(builds, list) or not builds:
        raise EnrollmentDenied("protected fixed build records are required")

    service_catalog = ProtectedEnrollmentCatalog.from_verified_records(
        records, protected_digest=digest, expected_uid=expected_uid,
        native_packages=getattr(enrollment, "native_package_records", None),
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
                or profile.profile_id in process_profiles):
            raise EnrollmentDenied("service generation identity does not match its authority principal")
        # Every child executable is selected by immutable artifact identity and
        # digest from the root-loaded artifact catalog; the worker supplies none.
        child_refs: dict[str, str] = {}
        for artifact_id in profile.runtime_artifact_ids:
            spec = artifact_catalog.artifacts.get(artifact_id)
            if spec is None:
                raise EnrollmentDenied("service runtime artifact is absent from the protected artifact catalog")
            child_refs[f"artifact:{artifact_id}:{spec.sha256}"] = spec.sha256
        process_profiles[profile.profile_id] = profile.as_managed_profile(
            artifact_root=enrollment.artifact_staging_directory,
            child_artifact_refs=child_refs,
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
        ),
        expected_uid=expected_uid, authorization_check=authorization_check,
    ))

    return RootRuntimeBindings(
        enrollment_catalog=service_catalog,
        build_catalog=build_catalog,
        device_catalog=device_catalog,
        process_manager=process_manager,
        effect_handlers=MappingProxyType(effect_handlers),
        native_bridges=MappingProxyType(dict(enrollment.native_bridges)),
    )
