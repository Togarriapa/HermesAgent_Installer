"""Composition of verified root enrollment into fixed authority handlers.

This module is deliberately downstream of the authority file verifier. It does
not parse caller data, choose a path, or accept worker supplied factories.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping

from hermes_installer.protected_enrollment import (
    EnrollmentDenied,
    ProtectedBuildCatalog,
    ProtectedDeviceCatalog,
    ProtectedEnrollmentCatalog,
    ProtectedRootJournalCatalog,
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
    native_package_resolver: Callable[[str, str], Any | None] | None = None
    remote_session_enrollments: Mapping[str, Any] = MappingProxyType({})
    process_profiles: Mapping[str, Any] = MappingProxyType({})
    protected_principal_bindings: tuple[Any, ...] = ()
    root_journal_catalog: ProtectedRootJournalCatalog | None = None
    source_observer_enrollments: Mapping[str, Any] = MappingProxyType({})

    def resolve_root_journal(self, root_id: str, *,
                              expected_active_generation_digest: str) -> Any:
        catalog = self.root_journal_catalog
        if catalog is None:
            raise EnrollmentDenied("protected root journal catalog is unavailable")
        return catalog.resolve(
            root_id, expected_active_generation_digest=expected_active_generation_digest,
        )

    def resolve_selected_native_principal(
        self, profile_id: str, generation: str, service_generation_digest: str,
    ) -> Any:
        """Return the one existing authority principal bound to a current native profile.

        The profile selector is only a lookup key. Identity comes from the
        verified PrincipalBinding collection, and its UID/namespace/principal
        must still match both the active service catalog and managed profile.
        """
        catalog = self.enrollment_catalog
        if (not isinstance(service_generation_digest, str)
                or service_generation_digest != getattr(catalog, "digest", None)):
            raise EnrollmentDenied("selected native principal belongs to a stale service catalog")
        try:
            service = catalog.resolve_profile_generation(profile_id, generation)
        except (AttributeError, EnrollmentDenied, TypeError, ValueError, PermissionError):
            raise EnrollmentDenied("selected native profile generation is absent or stale") from None
        managed = self.process_profiles.get(profile_id)
        if (managed is None or service.profile_id != profile_id
                or service.generation != generation
                or managed.profile_id != profile_id or managed.generation != generation
                or managed.owner_uid != service.service_uid
                or managed.owner_gid != service.service_gid
                or managed.enrollment_id != service.enrollment_id):
            raise EnrollmentDenied("selected native service identity no longer matches managed custody")
        matches = [binding for binding in self.protected_principal_bindings
                   if getattr(binding, "profile_id", None) == profile_id]
        if len(matches) != 1:
            raise EnrollmentDenied("selected native profile principal is absent or ambiguous")
        binding = matches[0]
        if (getattr(binding, "uid", None) != service.service_uid
                or getattr(binding, "uid", None) != managed.owner_uid
                or getattr(binding, "principal_id", None) != service.principal_id
                or getattr(binding, "namespace_id", None) != service.namespace_identity):
            raise EnrollmentDenied("selected native principal does not match the protected service UID and namespace")
        return binding

    def resolve_build_process_profile(self, target_id: str, generation: str) -> Any:
        """Return the selected dedicated build ManagedProfileCustody, never a path."""
        build, service = self.build_catalog.resolve_service(
            target_id, generation, self.enrollment_catalog)
        selected = self.process_profiles.get(service.profile_id)
        if (selected is None or selected.enrollment_id != service.enrollment_id
                or selected.generation != service.generation
                or selected.owner_uid != build.output_owner_uid
                or selected.owner_gid != service.service_gid
                or selected.operation_targets.get("process.start") != target_id):
            raise EnrollmentDenied("dedicated build process custody is unavailable or stale")
        return selected

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
        # The closure digest is over the complete native manifest file list;
        # the protected artifact catalog separately pins the archive bytes.
        # Do not compare those distinct digest domains.
        closure_spec = self.artifact_catalog.artifacts.get(package.compiled_closure_artifact_id)
        if closure_spec is None or not closure_spec.tree_files:
            raise EnrollmentDenied("native package closure is absent from the protected artifact catalog")
        pins = [(package.entrypoint_artifact_id, package.entrypoint_sha256),
                (package.resolver_artifact_id, package.resolver_sha256)]
        pins.extend((adapter.adapter_artifact_id, adapter.adapter_sha256)
                    for adapter in package.adapter_records.values())
        pins.extend((workflow["workflow_artifact_id"], workflow["workflow_sha256"])
                    for adapter in package.adapter_records.values()
                    for workflow in adapter.workflow_bindings)
        for artifact_id, digest in pins:
            spec = self.artifact_catalog.artifacts.get(artifact_id)
            if spec is None or spec.sha256 != digest:
                raise EnrollmentDenied("native package artifact pin is absent from protected catalog")
        return package

    def resolve_device(self, enrollment_id: str, generation: str) -> Any:
        return self.enrollment_catalog.resolve_device(
            enrollment_id, generation, self.device_catalog,
        )


def _unique_native_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate native manifest key")
        result[key] = value
    return result


def _build_native_package_resolver(*, enrollment: Any, catalog: Any,
                                   artifact_catalog: Any, staging_root: Any,
                                   expected_uid: int) -> Callable[[str, str], Any | None]:
    """Resolve the unique root-selected package and materialize its pinned closure."""
    from hermes_installer.managed_process_custodian import ManagedNativePackageMount

    raw_records = getattr(enrollment, "native_package_records", ())
    source_profiles = {
        (row.producer_profile_id, row.generation)
        for row in getattr(enrollment, "source_issuers", ())
    }

    def resolve(profile_id: str, generation: str) -> Any | None:
        matches = [row for row in raw_records
                   if row.get("profile_id") == profile_id and row.get("generation") == generation]
        if not matches:
            if (profile_id, generation) in source_profiles:
                raise EnrollmentDenied("source issuer has no selected native package closure")
            return None
        if len(matches) != 1:
            raise EnrollmentDenied("selected profile generation has ambiguous native packages")
        raw = matches[0]
        package = catalog.resolve_native_package(raw["package_id"], generation)
        closure_spec = artifact_catalog.artifacts.get(package.compiled_closure_artifact_id)
        if closure_spec is None or not closure_spec.tree_files:
            raise EnrollmentDenied("native package closure artifact is not a protected tree")
        closure = artifact_catalog.materialize_tree(
            package.compiled_closure_artifact_id, closure_spec.sha256,
            staging_root, expected_uid=expected_uid,
        )
        entrypoint = artifact_catalog.resolve(
            package.entrypoint_artifact_id, package.entrypoint_sha256,
            staging_root, expected_uid=expected_uid,
        )
        resolver_artifact = artifact_catalog.resolve(
            package.resolver_artifact_id, package.resolver_sha256,
            staging_root, expected_uid=expected_uid,
        )
        adapter_paths = {}
        for adapter_id, adapter in package.adapter_records.items():
            adapter_paths[adapter_id] = artifact_catalog.resolve(
                adapter.adapter_artifact_id, adapter.adapter_sha256,
                staging_root, expected_uid=expected_uid,
            )
        try:
            manifest_bytes = entrypoint.path.read_bytes()
            manifest = json.loads(manifest_bytes.decode("utf-8"),
                                  object_pairs_hook=_unique_native_json_pairs)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            raise EnrollmentDenied("selected native package manifest is unavailable or malformed") from None
        expected = {"schema", "package_id", "profile_id", "generation",
                    "closure_files", "adapters", "dependencies"}
        if (not isinstance(manifest, dict) or set(manifest) != expected
                or type(manifest["schema"]) is not int or manifest["schema"] != 1
                or manifest["package_id"] != package.package_id
                or manifest["profile_id"] != profile_id
                or manifest["generation"] != generation
                or not isinstance(manifest["dependencies"], list)
                or len(manifest["dependencies"]) > 256):
            raise EnrollmentDenied("selected native package manifest does not match protected enrollment")
        dependency_paths = {}
        for dependency in manifest["dependencies"]:
            if (not isinstance(dependency, dict)
                    or set(dependency) != {"artifact_id", "sha256", "module_names"}
                    or not isinstance(dependency["artifact_id"], str)
                    or dependency["artifact_id"] in dependency_paths
                    or not isinstance(dependency["sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", dependency["sha256"])):
                raise EnrollmentDenied("selected native dependency manifest is malformed")
            dependency_paths[dependency["artifact_id"]] = artifact_catalog.resolve(
                dependency["artifact_id"], dependency["sha256"],
                staging_root, expected_uid=expected_uid,
            )
        return ManagedNativePackageMount(
            package, profile_id, generation, closure, entrypoint,
            resolver_artifact, MappingProxyType(adapter_paths),
            MappingProxyType(dependency_paths),
        )

    return resolve

def _load_optional_package_sets(*, catalog: Any, signing_key: bytes,
                                key_id: str, expected_uid: int) -> Mapping[str, Any]:
    """Load package enrollment when present; only a missing leaf is optional.

    A present symlink, unreadable file, invalid parent, or malformed manifest
    still fails closed. This lets unrelated process/connector handlers start
    before a Coral package set has been separately enrolled.
    """
    from hermes_installer import artifacts

    path = artifacts.PACKAGE_SET_MANIFEST_PATH
    try:
        path.lstat()
    except FileNotFoundError:
        # The leaf alone may be absent. The fixed parent must already be
        # protected; an absent or replaceable enrollment directory is not an
        # invitation to silently continue.
        artifacts._secure_directory(path.parent, expected_uid)
        return MappingProxyType({})
    except OSError:
        raise EnrollmentDenied("protected package-set manifest cannot be inspected") from None
    return artifacts.load_protected_package_sets(
        path, catalog=catalog, signing_key=signing_key,
        key_id=key_id, expected_uid=expected_uid,
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
        "root_journal_root_records",
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
        source_issuers=getattr(enrollment, "source_issuers", None),
        memory_enrollments=getattr(enrollment, "memory_enrollments", None),
        parameter_schemas=getattr(enrollment, "operation_parameter_schemas", None),
    )
    build_catalog = ProtectedBuildCatalog.from_protected_records(
        builds, service_generation_digest=digest,
    )
    root_journal_catalog = ProtectedRootJournalCatalog.from_protected_records(
        enrollment.root_journal_root_records, generation_digest=digest,
    )
    for raw in builds:
        try:
            build_catalog.resolve_service(raw["target_id"], raw["generation"], service_catalog)
        except (KeyError, TypeError, ValueError, PermissionError):
            raise EnrollmentDenied(
                "protected build target has no exact dedicated service enrollment join") from None
    device_catalog = ProtectedDeviceCatalog.from_protected_records(devices)

    process_profiles = {}
    profile_to_principal: dict[str, tuple[int, Any]] = {}
    for uid, binding in enrollment.bindings_by_uid.items():
        if binding.profile_id in profile_to_principal:
            raise EnrollmentDenied("authority principal profile binding is duplicated")
        profile_to_principal[binding.profile_id] = (uid, binding)
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
    if "artifact_resolver" in manager_options or "native_package_resolver" in manager_options:
        raise EnrollmentDenied("artifact and native package resolvers are fixed by the verified root catalog")
    manager_options["artifact_resolver"] = lambda store_id, sha256: artifact_catalog.resolve_store_id(
        store_id, enrollment.artifact_staging_directory, expected_uid=expected_uid,
    )
    native_package_resolver = _build_native_package_resolver(
        enrollment=enrollment, catalog=service_catalog,
        artifact_catalog=artifact_catalog,
        staging_root=enrollment.artifact_staging_directory,
        expected_uid=expected_uid,
    )
    manager_options["native_package_resolver"] = native_package_resolver
    process_manager = create_managed_process_handler(process_profiles, **manager_options)

    remote_session_enrollments: Mapping[str, Any] = MappingProxyType({})
    remote_records = getattr(enrollment, "remote_session_records", ())
    if remote_records:
        principal_bindings: dict[str, Mapping[str, str]] = {}
        identities = enrollment.policy.enrollment.principal_identities
        for binding in enrollment.bindings_by_uid.values():
            identity = identities.get(binding.principal_id)
            subject = getattr(identity, "subject_id", None)
            if identity is None or not isinstance(subject, str) or not subject:
                continue
            if subject in principal_bindings:
                raise EnrollmentDenied("remote Access subjects are duplicated in protected principals")
            principal_bindings[subject] = MappingProxyType({
                "principal_id": binding.principal_id,
                "profile_id": binding.profile_id,
                "email": identity.email.casefold(),
            })
        role_artifacts = {
            artifact_id: spec.sha256
            for artifact_id, spec in artifact_catalog.artifacts.items()
        }
        try:
            from .remote_enrollment import parse_remote_session_enrollments
            remote_session_enrollments = parse_remote_session_enrollments(
                remote_records, principal_bindings=principal_bindings,
                process_profiles=process_profiles, role_artifacts=role_artifacts,
            )
        except (ImportError, AttributeError, KeyError, TypeError, ValueError, PermissionError):
            raise EnrollmentDenied("active remote-session records do not join the protected root catalogs") from None

    from hermes_installer.artifacts import build_artifact_handlers
    artifact_handlers = dict(build_artifact_handlers(
        artifact_catalog, enrollment.artifact_staging_directory,
        expected_uid=expected_uid, authorization_check=authorization_check,
    ))
    effect_handlers = {key: handler for key, handler in artifact_handlers.items()
                       if key[0] == "artifact.fetch"}
    for key, handler in process_manager.handlers().items():
        if key in effect_handlers:
            raise EnrollmentDenied("managed process handler conflicts with an existing root handler")
        effect_handlers[key] = handler

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
    from hermes_installer.artifacts import build_package_set_handlers
    package_sets = _load_optional_package_sets(
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
    if package_sets:
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
        native_package_resolver=native_package_resolver,
        remote_session_enrollments=remote_session_enrollments,
        process_profiles=MappingProxyType(dict(process_profiles)),
        protected_principal_bindings=tuple(enrollment.bindings_by_uid.values()),
        root_journal_catalog=root_journal_catalog,
        source_observer_enrollments=_derive_source_observer_enrollments(
            catalog=service_catalog, process_profiles=process_profiles,
            artifact_catalog=artifact_catalog,
        ),
    )


def _derive_source_observer_enrollments(*, catalog: Any, process_profiles: Mapping[str, Any],
                                        artifact_catalog: Any) -> Mapping[str, Any]:
    """Derive immutable observer metadata from explicit issuer/package joins.

    Returned rows are registration candidates only. The source registry still
    requires live PIDFD, loaded-closure, current invocation and target-peer
    proofs before it can issue a receipt.
    """
    from .source_observers import SourceObserverEnrollment

    channel_kinds = {
        "native-input": "native-input", "tool-result": "tool-result",
        "memory-result": "memory-record", "delegated-child": "tool-result",
        "schedule-event": "schedule-event", "webhook-event": "webhook-event",
    }
    def selected_kind(channel: str, adapter: Any) -> str | None:
        if channel == "effect-result":
            return "provider-result" if adapter.operation == "provider.dispatch" else "tool-result"
        return channel_kinds.get(channel)

    parent_kind_candidates: dict[str, set[str]] = {}
    for selected_join in catalog.source_observer_joins.values():
        selected_issuer = selected_join.issuer
        selected_kind_value = selected_kind(selected_issuer.issuer_channel_id, selected_join.adapter)
        if selected_kind_value is not None:
            parent_kind_candidates.setdefault(selected_issuer.issuer_channel_id, set()).add(selected_kind_value)
    result: dict[str, Any] = {}
    for observer_id, join in catalog.source_observer_joins.items():
        issuer, package, adapter = join.issuer, join.package, join.adapter
        service = catalog.resolve_profile_generation(package.profile_id, package.generation)
        artifact = artifact_catalog.artifacts.get(adapter.adapter_artifact_id)
        if artifact is None or artifact.sha256 != adapter.adapter_sha256:
            raise EnrollmentDenied("native source observer role is absent from protected artifact catalog")
        source_kind = selected_kind(issuer.issuer_channel_id, adapter)
        if source_kind is None:
            raise EnrollmentDenied("source observer channel has no fixed source kind mapping")
        parent_kinds = set()
        for parent in issuer.allowed_parent_channels:
            candidates = parent_kind_candidates.get(parent, set())
            if len(candidates) != 1:
                raise EnrollmentDenied("source observer parent channel has no fixed source kind mapping")
            parent_kinds.update(candidates)
        for action_id in issuer.source_action_ids:
            record = {
                "observer_enrollment_id": observer_id, "source_kind": source_kind,
                "origin_id": observer_id, "profile_id": service.profile_id,
                "principal_id": service.principal_id, "namespace_id": service.namespace_identity,
                "enrollment_id": service.enrollment_id, "generation": package.generation,
                "producer_uid": service.service_uid,
                "producer_executable_sha256": service.executable_sha256,
                "package_id": package.package_id, "package_sha256": package.compiled_closure_sha256,
                "role_id": adapter.adapter_id, "role_artifact_id": adapter.adapter_artifact_id,
                "role_sha256": adapter.adapter_sha256, "channel_id": issuer.issuer_channel_id,
                "capture_schema_id": issuer.capture_schema_id, "source_action_id": action_id,
                "target_id": adapter.target_id, "recipient": adapter.recipient,
                "allowed_parent_source_kinds": sorted(parent_kinds),
            }
            if observer_id in result:
                raise EnrollmentDenied("source observer enrollment expands ambiguously")
            result[observer_id] = SourceObserverEnrollment.from_protected_record(record)
    return MappingProxyType(result)
