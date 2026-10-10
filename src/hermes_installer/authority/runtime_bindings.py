"""Composition of verified root enrollment into fixed authority handlers.

This module is deliberately downstream of the authority file verifier. It does
not parse caller data, choose a path, or accept worker supplied factories.
"""
from __future__ import annotations

import json
import hashlib
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
class SelectedGatewayBoundary:
    remote_enrollment_id: str
    gateway_profile_id: str
    gateway_generation: str
    gateway_identity_digest: str
    hostname: str
    listener_port: int
    policy_config_digest: str
    policy_revision: str


@dataclass(frozen=True, slots=True)
class SelectedNativeWindow:
    remote_enrollment_id: str
    native_profile_id: str
    native_generation: str
    display_server_profile_id: str
    display_server_generation: str
    display_name: str
    xauthority_receipt_handle: str


@dataclass(frozen=True, slots=True)
class ResourceCredentialBinding:
    """Root-only mapping from a pinned adapter placeholder to a vault reference."""
    backend_enrollment_id: str
    resource_id: str
    profile_id: str
    profile_generation: str
    resource_generation: str
    observer_enrollment_id: str
    source_placeholder: str
    credential_reference_id: str
    usage: str


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
    native_mcp_tool_binding_records: tuple[Mapping[str, Any], ...] = ()
    native_schema_artifact_records: tuple[Mapping[str, Any], ...] = ()
    composio_channel_enrollment_records: tuple[Mapping[str, Any], ...] = ()
    channel_delivery_binding_records: tuple[Mapping[str, Any], ...] = ()
    resource_job_records: tuple[Mapping[str, Any], ...] = ()
    protected_rules: Mapping[tuple[str, str, str], Any] = MappingProxyType({})
    mcp_services: Mapping[str, Any] = MappingProxyType({})
    remote_observation_records: tuple[Mapping[str, Any], ...] = ()
    remote_session_records: tuple[Mapping[str, Any], ...] = ()
    resource_credential_bindings: Mapping[tuple[str, str], ResourceCredentialBinding] = MappingProxyType({})
    resource_controller_role_records: tuple[Mapping[str, Any], ...] = ()
    resource_backend_records: tuple[Mapping[str, Any], ...] = ()

    def resolve_composio_channel_enrollment(self, enrollment_id: str,
                                            resource_generation: str) -> Mapping[str, Any]:
        """Return one channel row only after active resource, issuer and controller joins."""
        rows = [row for row in self.composio_channel_enrollment_records
                if row.get("id") == enrollment_id and row.get("resource_generation") == resource_generation]
        if len(rows) != 1:
            raise EnrollmentDenied("Composio channel enrollment is absent or ambiguous")
        row = rows[0]
        resource = [candidate for candidate in self.resource_job_records
                    if candidate.get("resource_id") == row.get("channel_resource_id")
                    and candidate.get("generation") == resource_generation
                    and candidate.get("profile_id") == row.get("profile_id")]
        issuer = self.source_observer_enrollments.get(row.get("source_issuer_id"))
        role = [candidate for candidate in self.resource_controller_role_records
                if candidate.get("id") == row.get("controller_role_id")
                and candidate.get("controller_kind") == "root-channel"
                and row.get("source_issuer_id") in candidate.get("source_observer_enrollment_ids", ())]
        if (len(resource) != 1 or issuer is None or len(role) != 1
                or getattr(issuer, "profile_id", None) != row.get("profile_id")
                or getattr(issuer, "generation", None) != getattr(self.process_profiles.get(row.get("profile_id")), "generation", None)):
            raise EnrollmentDenied("Composio channel row does not join current protected resource/controller/observer")
        # Account/setup receipt handles still require their own root verifier;
        # this metadata accessor does not make discovery or labels proof.
        return row

    def resolve_channel_delivery_binding(
        self, binding_id: str, profile_id: str, process_generation: str,
        native_package_id: str, native_package_generation: str,
    ) -> Mapping[str, Any]:
        rows = [row for row in self.channel_delivery_binding_records
                if row.get("id") == binding_id and row.get("profile_id") == profile_id
                and row.get("process_generation") == process_generation
                and row.get("native_package_id") == native_package_id
                and row.get("native_package_generation") == native_package_generation]
        if len(rows) != 1:
            raise EnrollmentDenied("channel delivery binding is absent or ambiguous")
        package = self.resolve_native_package(native_package_id, native_package_generation)
        if package.profile_id != profile_id or package.generation != process_generation:
            raise EnrollmentDenied("channel delivery package does not join the selected process generation")
        row = rows[0]
        for observer_id in row["source_observer_enrollment_ids"]:
            observer = self.source_observer_enrollments.get(observer_id)
            if (observer is None or observer.profile_id != profile_id
                    or observer.generation != process_generation
                    or observer.package_id != native_package_id):
                raise EnrollmentDenied("channel delivery observer does not join the selected native package")
        return row

    def resolve_native_schema_record(
        self, schema_id: str, native_package_id: str, native_package_generation: str,
        adapter_id: str, action_id: str, schema_kind: str,
    ) -> Mapping[str, Any]:
        """Select one digest-bound schema artifact row joined to current actions.

        This does not treat the opaque source receipt handle as proof and does
        not parse bytes. The native schema catalog must verify receipt
        membership and resolve the actual root-owned artifact before exposing
        a schema body.
        """
        if schema_kind not in {"arguments", "result"}:
            raise EnrollmentDenied("native schema kind is invalid")
        try:
            # The package resolver verifies the selected immutable workflow
            # artifact ID/SHA pins as well as the active package generation.
            package = self.resolve_native_package(native_package_id, native_package_generation)
        except Exception:
            raise EnrollmentDenied("native schema package generation is unavailable") from None
        adapter = package.adapter_records.get(adapter_id)
        if adapter is None or adapter.action_id != action_id:
            raise EnrollmentDenied("native schema does not join an active package adapter action")
        expected_schema_id = (adapter.argument_schema_id if schema_kind == "arguments"
                              else adapter.result_schema_id)
        eligible = schema_id == expected_schema_id
        # External workflow schemas are selected by the package's strict
        # adapter_workflow_bindings, whose artifact IDs/SHA pins were checked
        # by resolve_native_package above. The schema-artifact row remains
        # bound to the enclosing package adapter action, while the workflow
        # binding supplies the exact external action/schema association.
        if not eligible:
            workflow_schema_field = ("external_argument_schema_id" if schema_kind == "arguments"
                                     else "external_result_schema_id")
            matching_workflows = [workflow for workflow in adapter.workflow_bindings
                                  if workflow.get(workflow_schema_field) == schema_id]
            if len(matching_workflows) > 1:
                raise EnrollmentDenied("native workflow schema is ambiguous across selected external actions")
            if len(matching_workflows) == 1:
                workflow = matching_workflows[0]
                if not all(workflow.get(name) for name in (
                    "external_tool_name", "external_action_id", "workflow_artifact_id", "workflow_sha256",
                )):
                    raise EnrollmentDenied("native workflow schema lacks its exact selected action binding")
                eligible = True
        if not eligible:
            # Native MCP request/result schemas are separately selected by the
            # protected MCP dispatch rows but still use the exact package,
            # action and fixed dispatch adapter.
            eligible = any(
                row.get("id") == action_id
                and row.get("native_package_id") == native_package_id
                and row.get("native_package_generation") == native_package_generation
                and adapter_id == "hermes-installer.native-mcp-dispatch.v1"
                and row.get("handler_artifact_id") == adapter.adapter_artifact_id
                and row.get("handler_artifact_sha256") == adapter.adapter_sha256
                and row.get("request_schema_id" if schema_kind == "arguments" else "result_schema_id") == schema_id
                for row in self.native_mcp_tool_binding_records
            )
        if not eligible:
            raise EnrollmentDenied("native schema ID is not selected by the exact package/action")
        matches = [row for row in self.native_schema_artifact_records
                   if row.get("id") == schema_id
                   and row.get("native_package_id") == native_package_id
                   and row.get("native_package_generation") == native_package_generation
                   and row.get("adapter_id") == adapter_id
                   and row.get("action_id") == action_id
                   and row.get("schema_kind") == schema_kind]
        if len(matches) != 1:
            raise EnrollmentDenied("native schema artifact is absent or ambiguous in the active generation")
        return matches[0]

    def _remote_observation_join(self, remote_enrollment_id: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        if not isinstance(remote_enrollment_id, str) or not remote_enrollment_id:
            raise EnrollmentDenied("remote observation enrollment ID is invalid")
        observations = [row for row in self.remote_observation_records
                        if row.get("remote_enrollment_id") == remote_enrollment_id]
        sessions = [row for row in self.remote_session_records if row.get("id") == remote_enrollment_id]
        if len(observations) != 1 or len(sessions) != 1:
            raise EnrollmentDenied("remote observation selection is absent or ambiguous")
        return observations[0], sessions[0]

    def selected_gateway_boundary(self, remote_enrollment_id: str) -> SelectedGatewayBoundary:
        """Select the active gateway boundary and bind it to current custody proof."""
        observation, remote = self._remote_observation_join(remote_enrollment_id)
        profile_id = remote["gateway_profile_id"]
        process_profile = self.process_profiles.get(profile_id)
        generation = getattr(process_profile, "generation", None)
        if not isinstance(generation, str) or not generation:
            raise EnrollmentDenied("remote gateway generation is not currently enrolled")
        proof_resolver = getattr(self.process_manager, "inspect_enrolled_process", None)
        proof = proof_resolver(profile_id, generation) if callable(proof_resolver) else None
        if (process_profile is None or process_profile.generation != generation or proof is None
                or proof.profile_id != profile_id or proof.profile_generation != generation
                or proof.enrollment_id != process_profile.enrollment_id
                or proof.uid != process_profile.owner_uid
                or proof.executable_sha256 != remote["gateway_role_sha256"]):
            raise EnrollmentDenied("selected gateway has no current matching custody role proof")
        identity = {
            "profile_id": proof.profile_id, "enrollment_id": proof.enrollment_id,
            "generation": proof.profile_generation, "uid": proof.uid, "gid": proof.gid,
            "pid": proof.pid, "starttime": proof.pid_starttime_ticks,
            "executable_device": proof.executable_device,
            "executable_inode": proof.executable_inode,
            "executable_sha256": proof.executable_sha256,
            "cgroup_id": proof.cgroup_id,
            "mount_namespace_inode": proof.mount_namespace_inode,
            "network_namespace_inode": proof.network_namespace_inode,
        }
        identity_digest = hashlib.sha256(json.dumps(
            identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        return SelectedGatewayBoundary(
            remote_enrollment_id=remote_enrollment_id,
            gateway_profile_id=profile_id, gateway_generation=generation,
            gateway_identity_digest=identity_digest,
            hostname=remote["expected_hostname"],
            listener_port=observation["gateway_listener_port"],
            policy_config_digest=remote["policy_config_digest"],
            policy_revision=remote["policy_revision"],
        )

    def selected_native_window(self, remote_enrollment_id: str) -> SelectedNativeWindow:
        """Return only the selected identity and opaque receipt handle.

        Physical Xauthority identity comes from the root startup receipt, never
        from this selection row or a caller-provided path.
        """
        observation, remote = self._remote_observation_join(remote_enrollment_id)
        profile_id = remote.get("native_desktop_profile_id")
        generation = remote.get("native_generation")
        if not isinstance(profile_id, str) or not isinstance(generation, str):
            raise EnrollmentDenied("selected native window process binding is incomplete")
        native = self.process_profiles.get(profile_id)
        display = self.process_profiles.get(observation["display_server_profile_id"])
        if (native is None or native.generation != generation
                or native.enrollment_id != observation["native_window_enrollment_id"]
                or display is None or display.generation != observation["display_server_generation"]
                or profile_id == observation["display_server_profile_id"]):
            raise EnrollmentDenied("selected native window has stale process profile bindings")
        return SelectedNativeWindow(
            remote_enrollment_id=remote_enrollment_id,
            native_profile_id=profile_id,
            native_generation=generation,
            display_server_profile_id=display.profile_id,
            display_server_generation=display.generation,
            display_name=observation["display_name"],
            xauthority_receipt_handle=observation["xauthority_receipt_handle"],
        )

    def resolve_resource_credential_binding(
        self, backend_enrollment_id: str, source_placeholder: str, usage: str, *,
        profile_id: str, profile_generation: str, resource_id: str,
        resource_generation: str, observer_enrollment_id: str,
        service_generation_digest: str,
    ) -> ResourceCredentialBinding:
        """Resolve one exact backend placeholder after all active runtime joins."""
        if service_generation_digest != self.enrollment_catalog.digest:
            raise EnrollmentDenied("resource credential binding belongs to a stale service generation")
        binding = self.resource_credential_bindings.get((backend_enrollment_id, source_placeholder))
        if (binding is None or binding.usage != usage or binding.profile_id != profile_id
                or binding.profile_generation != profile_generation
                or binding.resource_id != resource_id or binding.resource_generation != resource_generation
                or binding.observer_enrollment_id != observer_enrollment_id):
            raise EnrollmentDenied("resource credential placeholder does not match its current protected backend")
        service = self.enrollment_catalog.resolve_profile_generation(profile_id, profile_generation)
        if (service.profile_id != profile_id or service.generation != profile_generation
                or not any(join.issuer.observer_enrollment_id == observer_enrollment_id
                           and join.package.profile_id == profile_id
                           and join.package.generation == profile_generation
                           for join in self.enrollment_catalog.source_observer_joins.values())):
            raise EnrollmentDenied("resource credential binding lacks current native source/package proof join")
        return binding

    def resolve_resource_controller_role(
        self, controller_id: str, service_generation_digest: str,
    ) -> Mapping[str, Any]:
        """Resolve protected controller metadata after active observer/backend joins.

        This is selection metadata only; a live root process proof remains
        necessary before any controller effects can be registered.
        """
        if service_generation_digest != self.enrollment_catalog.digest:
            raise EnrollmentDenied("resource controller role belongs to a stale service generation")
        matches = [row for row in self.resource_controller_role_records
                   if row.get("id") == controller_id]
        if len(matches) != 1:
            raise EnrollmentDenied("resource controller role is absent or ambiguous")
        row = matches[0]
        issuers = {issuer.observer_enrollment_id: issuer
                   for issuer in self.enrollment_catalog.source_issuers}
        backend_ids = {backend.get("id") for backend in self.resource_backend_records}
        if (not row["source_observer_enrollment_ids"]
                or any(observer_id not in issuers
                       for observer_id in row["source_observer_enrollment_ids"])
                or any(backend_id not in backend_ids
                       for backend_id in row["allowed_backend_enrollment_ids"])):
            raise EnrollmentDenied("resource controller role lacks its active observer/backend joins")
        for artifact_id, expected_sha in (
                (row["daemon_executable_artifact_id"], row["daemon_executable_sha256"]),
                (row["role_module_artifact_id"], row["role_module_sha256"])):
            artifact = self.artifact_catalog.artifacts.get(artifact_id)
            if artifact is None or artifact.sha256 != expected_sha:
                raise EnrollmentDenied("resource controller artifact does not match its protected catalog pin")
        return MappingProxyType(dict(row))

    def resolve_native_mcp_tool_bindings(
        self, profile_id: str, process_generation: str, service_generation_digest: str,
    ) -> tuple[Mapping[str, Any], ...]:
        """Return only exact active MCP dispatch rows joined to current service/package authority."""
        if (service_generation_digest != self.enrollment_catalog.digest
                or not isinstance(profile_id, str) or not isinstance(process_generation, str)):
            raise EnrollmentDenied("native MCP binding belongs to a stale service catalog")
        try:
            service_profile = self.enrollment_catalog.resolve_profile_generation(profile_id, process_generation)
        except (AttributeError, EnrollmentDenied, TypeError, ValueError):
            raise EnrollmentDenied("native MCP process generation is not currently enrolled") from None
        if (self.process_profiles.get(profile_id) is None
                or self.process_profiles[profile_id].generation != process_generation
                or self.process_profiles[profile_id].enrollment_id != service_profile.enrollment_id):
            raise EnrollmentDenied("native MCP process custody does not match active enrollment")
        selected = tuple(row for row in self.native_mcp_tool_binding_records
                         if row.get("profile_id") == profile_id
                         and row.get("process_generation") == process_generation)
        for row in selected:
            package = self.enrollment_catalog.resolve_native_package(
                row["native_package_id"], row["native_package_generation"],
            )
            if (package.profile_id != profile_id or package.generation != process_generation):
                raise EnrollmentDenied("native MCP binding package is stale or belongs to another profile")
            adapter = package.adapter_records.get("hermes-installer.native-mcp-dispatch.v1")
            if (adapter is None or adapter.action_id != row["id"]
                    or adapter.generation != row["native_package_generation"]
                    or adapter.adapter_artifact_id != row["handler_artifact_id"]
                    or adapter.adapter_sha256 != row["handler_artifact_sha256"]):
                raise EnrollmentDenied("native MCP handler does not join the selected immutable package adapter")
            mcp_service = self.mcp_services.get(row["mcp_enrollment_id"])
            if (mcp_service is None or mcp_service.get("id") != row["mcp_enrollment_id"]
                    or row["mcp_tool_name"] not in mcp_service.get("allowed_tools", ())
                    or set(scope["argument_field"] for scope in row["scope_bindings"])
                    != set(mcp_service.get("selection_arguments", {}).get(row["mcp_tool_name"], ()))):
                raise EnrollmentDenied("native MCP selected service/tool/scope is not enrolled")
            channel = mcp_service.get("channel")
            expected_operation = "mcp.request" if channel == "http" else "mcp.stdio" if channel == "stdio" else None
            expected_target = f"mcp:{row['mcp_enrollment_id']}:{channel}"
            expected_capability = f"mcp:{row['mcp_enrollment_id']}:read"
            rule = self.protected_rules.get((row["capability"], row["effect_operation"], row["effect_target"]))
            if (expected_operation is None or row["effect_operation"] != expected_operation
                    or row["effect_target"] != expected_target or row["capability"] != expected_capability
                    or row["recipient"] is not None or rule is None):
                raise EnrollmentDenied("native MCP effect target lacks exact selected authority rule")
        return selected

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

    def resolve_native_bridge_role_artifact(self, bridge_id: str, role: str) -> tuple[str, str]:
        """Resolve a bridge peer's role artifact from its unique protected native closure."""
        bridge = self.native_bridges.get(bridge_id)
        if bridge is None or role not in {"producer", "gateway"}:
            raise EnrollmentDenied("native bridge role is absent or invalid")
        profile_id = bridge.producer_profile_id if role == "producer" else bridge.gateway_profile_id
        generation = bridge.producer_generation if role == "producer" else bridge.gateway_generation
        package = self.enrollment_catalog.resolve_profile_native_package(profile_id, generation)
        peer_profiles = {
            bridge.producer_profile_id: bridge.producer_generation,
            bridge.gateway_profile_id: bridge.gateway_generation,
        }
        for binding in bridge.observer_delivery_bindings:
            join = self.enrollment_catalog.source_observer_joins.get(binding.observer_enrollment_id)
            if (join is None or join.package.profile_id not in peer_profiles
                    or join.package.generation != peer_profiles[join.package.profile_id]
                    or join.issuer.producer_profile_id != join.package.profile_id
                    or join.issuer.generation != join.package.generation):
                raise EnrollmentDenied("native bridge observer role does not join a protected package")
        # The selected peer role is the protected package entrypoint. Observer
        # rows pin action-adapter roles separately and must not be substituted
        # for the process role reported by the pending native pair.
        artifact_id, artifact_sha = package.entrypoint_artifact_id, package.entrypoint_sha256
        spec = self.artifact_catalog.artifacts.get(artifact_id)
        if spec is None or spec.sha256 != artifact_sha:
            raise EnrollmentDenied("native bridge role artifact is not present in the protected artifact catalog")
        return artifact_id, artifact_sha

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


def _derive_resource_credential_bindings(enrollment: Any) -> Mapping[tuple[str, str], ResourceCredentialBinding]:
    """Compile exact credential placeholder references from digest-verified rows."""
    rows = getattr(enrollment, "resource_backend_enrollment_records", None)
    if not isinstance(rows, (list, tuple)):
        raise EnrollmentDenied("active resource backend credential records are unavailable")
    allowed_usage = {"webhook-hmac-verify", "channel-account", "backend-account"}
    result: dict[tuple[str, str], ResourceCredentialBinding] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise EnrollmentDenied("active resource backend credential row is malformed")
        refs = row.get("credential_reference_ids")
        pairs = row.get("credential_bindings")
        if not isinstance(refs, (list, tuple)) or not isinstance(pairs, (list, tuple)):
            raise EnrollmentDenied("active resource backend credential row is incomplete")
        for pair in pairs:
            if not isinstance(pair, Mapping) or set(pair) != {
                    "source_placeholder", "credential_reference_id", "usage"}:
                raise EnrollmentDenied("active resource credential mapping has invalid fields")
            placeholder = pair["source_placeholder"]
            reference = pair["credential_reference_id"]
            usage = pair["usage"]
            if (not isinstance(placeholder, str) or not placeholder or len(placeholder) > 256
                    or any(ord(char) < 0x20 for char in placeholder)
                    or not isinstance(reference, str) or reference not in refs
                    or usage not in allowed_usage):
                raise EnrollmentDenied("active resource credential mapping is not allowlisted")
            key = (row["id"], placeholder)
            if key in result:
                raise EnrollmentDenied("active resource credential placeholder is duplicated")
            result[key] = ResourceCredentialBinding(
                backend_enrollment_id=row["id"], resource_id=row["resource_id"],
                profile_id=row["profile_id"], profile_generation=row["profile_generation"],
                resource_generation=row["generation"],
                observer_enrollment_id=row["observer_enrollment_id"],
                source_placeholder=placeholder, credential_reference_id=reference, usage=usage,
            )
    return MappingProxyType(result)


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
        "root_journal_root_records", "native_mcp_tool_binding_records",
        "resource_controller_role_records", "remote_observation_records",
        "native_schema_artifact_records",
        "composio_channel_enrollment_records", "channel_delivery_binding_records",
        "resource_backend_enrollment_records",
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
        native_mcp_tool_binding_records=tuple(enrollment.native_mcp_tool_binding_records),
        native_schema_artifact_records=tuple(enrollment.native_schema_artifact_records),
        composio_channel_enrollment_records=tuple(getattr(enrollment, "composio_channel_enrollment_records", ())),
        channel_delivery_binding_records=tuple(getattr(enrollment, "channel_delivery_binding_records", ())),
        resource_job_records=tuple(enrollment.resource_job_records),
        protected_rules=MappingProxyType(dict(enrollment.rules)),
        mcp_services=MappingProxyType(dict(enrollment.mcp_services)),
        remote_observation_records=tuple(enrollment.remote_observation_records),
        remote_session_records=tuple(enrollment.remote_session_records),
        resource_credential_bindings=_derive_resource_credential_bindings(enrollment),
        resource_controller_role_records=tuple(enrollment.resource_controller_role_records),
        resource_backend_records=tuple(enrollment.resource_backend_enrollment_records),
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
