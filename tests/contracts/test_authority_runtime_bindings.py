from types import SimpleNamespace

import pytest

from hermes_installer.authority.runtime_bindings import RootRuntimeBindings, build_root_runtime_bindings
from hermes_installer.protected_enrollment import EnrollmentDenied
from hermes_installer.authority.types import AuthorityDenied


def test_root_runtime_composition_fails_closed_without_verified_generation_records():
    enrollment = SimpleNamespace(
        key_id="test-key",
        bindings_by_uid={},
        rules={},
        process_profiles={},
        artifact_staging_directory="/unused",
        native_bridges={},
    )
    with pytest.raises(EnrollmentDenied, match="verified generation"):
        build_root_runtime_bindings(
            enrollment, vault=None, artifact_catalog=None,
            authorization_check=lambda **_: True,
        )


def test_root_runtime_composition_requires_service_records_before_optional_hardware_catalogs():
    enrollment = SimpleNamespace(
        key_id="test-key",
        bindings_by_uid={},
        rules={},
        process_profiles={},
        artifact_staging_directory="/unused",
        native_bridges={},
        service_records=[],
        protected_devices=[],
        protected_build_records=[],
        protected_enrollment_digest="a" * 64,
        root_journal_root_records=(),
        native_mcp_tool_binding_records=(), resource_controller_role_records=(),
        remote_observation_records=(), resource_backend_enrollment_records=(),
        native_schema_artifact_records=(),
        composio_channel_enrollment_records=(), channel_delivery_binding_records=(),
        remote_startup_records=(), private_loopback_network_records=(),
        selected_resource_execution_records=(), selected_application_runtime_records=(), resource_scope_binding_records=(), public_web_scope_records=(),
    )
    with pytest.raises(EnrollmentDenied, match="service generation records"):
        build_root_runtime_bindings(
            enrollment, vault=None, artifact_catalog=None,
            authorization_check=lambda **_: True,
        )


def test_root_runtime_private_memory_getters_forward_only_protected_binding_ids():
    from types import SimpleNamespace
    endpoint = SimpleNamespace(binding_id="endpoint-a", service_generation_digest="a" * 64)
    model = SimpleNamespace(binding_id="model-a", endpoint_binding_id="endpoint-a",
                            service_generation_digest="a" * 64)
    catalog = SimpleNamespace(
        resolve_private_memory_endpoint_binding=lambda binding_id: endpoint if binding_id == "endpoint-a" else None,
        resolve_private_memory_model_binding=lambda binding_id, endpoint_id=None:
            model if binding_id == "model-a" and endpoint_id in (None, "endpoint-a") else None,
    )
    artifact_catalog = SimpleNamespace(artifacts={
        "server-config-a": SimpleNamespace(sha256="a" * 64),
        "server-runtime-a": SimpleNamespace(sha256="b" * 64),
        "license-a": SimpleNamespace(sha256="c" * 64),
        "model-runtime-a": SimpleNamespace(sha256="e" * 64),
        "load-config-a": SimpleNamespace(sha256="f" * 64),
    })
    endpoint = SimpleNamespace(
        binding_id="endpoint-a", service_generation_digest="a" * 64,
        server_config_artifact_id="server-config-a", server_config_sha256="a" * 64,
        runtime_artifact_ids=("server-runtime-a",),
    )
    model = SimpleNamespace(
        binding_id="model-a", endpoint_binding_id="endpoint-a",
        service_generation_digest="a" * 64, license_artifact_id="license-a",
        license_sha256="c" * 64, model_artifact_id="existing-model:" + "d" * 64,
        model_artifact_sha256="d" * 64, model_tree_manifest_sha256="d" * 64,
        runtime_artifact_id="model-runtime-a", runtime_artifact_sha256="e" * 64,
        load_config_artifact_id="load-config-a", load_config_sha256="f" * 64,
    )
    bindings = RootRuntimeBindings(
        enrollment_catalog=catalog, build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=artifact_catalog,
        build_store=None, service_connector=None,
    )
    assert bindings.resolve_private_memory_endpoint_binding("endpoint-a") is endpoint
    assert bindings.resolve_private_memory_model_binding("model-a", "endpoint-a") is model


def test_empty_device_and_build_catalogs_fail_only_when_selected():
    from hermes_installer.protected_enrollment import ProtectedBuildCatalog, ProtectedDeviceCatalog

    devices = ProtectedDeviceCatalog.from_protected_records([])
    builds = ProtectedBuildCatalog.from_protected_records([])
    with pytest.raises(EnrollmentDenied, match="stale"):
        devices.resolve("unavailable-device", "device-generation")
    with pytest.raises(EnrollmentDenied, match="stale"):
        builds.resolve("coral-cpython-build:start", "build-generation")


def test_selected_start_join_uses_fixed_recipe_and_effect_target():
    recipe = SimpleNamespace(
        process_start_target="root-fixed-start", enrollment_id="enrollment-a",
        generation="generation-a", profile_id="profile-a", principal_id="principal-a",
        service_uid=1001, service_gid=1001, operation_id="hermes-server-start-v1",
    )
    effect = SimpleNamespace(
        target="root-fixed-start", enrollment_id="enrollment-a", generation="generation-a",
        profile_id="profile-a", principal_id="principal-a", service_uid=1001, service_gid=1001,
    )
    catalog = SimpleNamespace(
        resolve_launch_recipe=lambda *_args: recipe,
        resolve_operation=lambda *_args: effect,
    )
    bindings = RootRuntimeBindings(
        enrollment_catalog=catalog, build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
        build_store=None, service_connector=None,
    )
    selected = bindings.resolve_selected_operation(
        "enrollment-a", "generation-a", "process.start", "hermes-server-start-v1",
    )
    assert (selected.operation, selected.operation_id, selected.target) == (
        "process.start", "hermes-server-start-v1", "root-fixed-start")
    assert (selected.profile_id, selected.principal_id, selected.service_uid) == (
        "profile-a", "principal-a", 1001)
    with pytest.raises(EnrollmentDenied, match="only protected process.start"):
        bindings.resolve_selected_operation(
            "enrollment-a", "generation-a", "process.stop", "hermes-server-start-v1",
        )


def test_selected_remote_startup_joins_services_recipes_network_and_overlay_catalog():
    digest = "a" * 64
    startup = {
        "id": "startup-a", "remote_enrollment_id": "remote-a",
        "display_enrollment_id": "display-enrollment", "display_generation": "display-gen",
        "display_operation_id": "native-display-start-v1",
        "gateway_enrollment_id": "gateway-enrollment", "gateway_generation": "gateway-gen",
        "gateway_operation_id": "native-remote-gateway-start-v1",
        "desktop_enrollment_id": "desktop-enrollment", "desktop_generation": "desktop-gen",
        "desktop_operation_id": "native-desktop-app-start-v1",
        "network_enrollment_id": "network-a", "xauthority_mount_id": "xauth-mount-a",
        "xpra_xauthority_overlay_artifact_id": "xpra-overlay-a",
        "xpra_xauthority_overlay_sha256": "b" * 64,
        "xpra_xauthority_patch_receipt_handle": "patch-receipt-a",
    }
    network = {
        "id": "network-a", "generation": "network-gen", "namespace_identity": "ns-a",
        "member_enrollment_ids": ["display-enrollment", "gateway-enrollment", "desktop-enrollment"],
        "listener_bindings": [{"enrollment_id": "gateway-enrollment", "role": "gateway",
                               "ipv4": "127.0.0.1", "port": 8743}],
        "client_bindings": [{"enrollment_id": "desktop-enrollment",
                             "listener_enrollment_id": "gateway-enrollment", "port": 8743}],
        "policy_artifact_id": "network-policy-a", "policy_sha256": "c" * 64,
    }

    class Catalog:
        def __init__(self):
            self.digest = digest
            self.services = {}
            for enrollment_id, profile_id, generation in (
                ("display-enrollment", "display-profile", "display-gen"),
                ("gateway-enrollment", "gateway-profile", "gateway-gen"),
                ("desktop-enrollment", "desktop-profile", "desktop-gen"),
            ):
                self.services[enrollment_id] = SimpleNamespace(
                    enrollment_id=enrollment_id, profile_id=profile_id, generation=generation,
                    principal_id=f"principal-{profile_id}", service_uid=1001, service_gid=1001,
                    namespace_identity="ns-a",
                )

        def resolve(self, enrollment_id, generation):
            service = self.services[enrollment_id]
            assert service.generation == generation
            return service

        def resolve_enrollment(self, enrollment_id):
            return self.services[enrollment_id]

        def resolve_operation(self, enrollment_id, generation, operation):
            return SimpleNamespace(profile_id=self.services[enrollment_id].profile_id,
                                   target=f"target-{enrollment_id}")

        def resolve_launch_recipe(self, enrollment_id, generation, operation_id):
            return SimpleNamespace(operation_id=operation_id,
                                   process_start_target=f"target-{enrollment_id}")

    catalog = Catalog()
    process_profiles = {
        service.profile_id: SimpleNamespace(
            profile_id=service.profile_id, generation=service.generation,
            enrollment_id=service.enrollment_id, owner_uid=service.service_uid,
            owner_gid=service.service_gid,
        ) for service in catalog.services.values()
    }
    binding = RootRuntimeBindings(
        enrollment_catalog=catalog, build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={},
        artifact_catalog=SimpleNamespace(artifacts={
            "network-policy-a": SimpleNamespace(sha256="c" * 64),
            "xpra-overlay-a": SimpleNamespace(sha256="b" * 64),
        }), build_store=None, service_connector=None,
        remote_session_enrollments={"remote-a": SimpleNamespace(
            session=SimpleNamespace(enrollment_id="remote-a"))},
        process_profiles=process_profiles,
        remote_session_records=({"id": "remote-a", "gateway_profile_id": "gateway-profile",
                                 "native_desktop_profile_id": "desktop-profile",
                                 "native_generation": "desktop-gen"},),
        remote_observation_records=({"id": "observation-a", "remote_enrollment_id": "remote-a",
                                     "native_window_enrollment_id": "desktop-enrollment",
                                     "display_server_profile_id": "display-profile",
                                     "display_server_generation": "display-gen",
                                     "display_name": ":0",
                                     "xauthority_receipt_handle": "xauth-receipt-a"},),
        remote_startup_records=(startup,), private_loopback_network_records=(network,),
    )
    selected = binding.resolve_remote_startup("remote-a")
    assert selected.service_generation_digest == digest
    assert (selected.display_enrollment_id, selected.gateway_operation_id,
            selected.desktop_service.profile_id) == (
                "display-enrollment", "native-remote-gateway-start-v1", "desktop-profile")
    assert selected.xpra_xauthority_patch_receipt_handle == "patch-receipt-a"
    assert (selected.native_profile_id, selected.native_generation,
            selected.display_name, selected.xauthority_reader_gid) == (
                "desktop-profile", "desktop-gen", ":0", 1001)

    with pytest.raises(EnrollmentDenied, match="stale service generation"):
        binding.resolve_private_loopback_network("network-a", service_generation_digest="d" * 64)


def test_selected_resource_record_is_metadata_only_and_joins_exact_scope_backend_and_rule():
    from types import SimpleNamespace

    digest = "a" * 64
    row = {
        "resource_id": "notice-hook", "resource_kind": "webhooks",
        "source_revision": "1" * 40, "source_manifest_sha256": "2" * 64,
        "resource_generation": "3" * 64, "profile_id": "profile-a",
        "profile_generation": "process-generation-a",
        "materialization_receipt_handle": "materialization-receipt-a",
        "materialized_member_path": "webhooks/notice-hook.yaml",
        "materialized_member_sha256": "4" * 64, "materialized_member_size_bytes": 512,
        "effective_spec_sha256": "5" * 64, "backend_enrollment_id": "backend-a",
        "operation": "resource.webhook.deliver", "capability": "webhook:deliver",
        "target_id": "resource:webhooks/notice-hook@1.0.0", "recipient": "recipient-a",
        "delegation_id": None, "enabled": True,
    }
    backend = {
        "id": "backend-a", "resource_id": row["resource_id"], "profile_id": row["profile_id"],
        "principal_id": "principal-a", "profile_generation": row["profile_generation"],
        "generation": row["resource_generation"], "operation": row["operation"],
        "target_id": row["target_id"], "recipient": row["recipient"], "scope_binding_id": "scope-a",
    }
    scope = {
        "id": "scope-a", "resource_id": row["resource_id"], "profile_id": row["profile_id"],
        "profile_generation": row["profile_generation"], "resource_generation": row["resource_generation"],
        "backend_enrollment_id": "backend-a",
    }
    class Catalog:
        def __init__(self):
            self.digest = digest
        def resolve_profile_generation(self, profile_id, generation):
            assert (profile_id, generation) == ("profile-a", "process-generation-a")
            return SimpleNamespace(profile_id=profile_id, generation=generation, principal_id="principal-a")

    binding = RootRuntimeBindings(
        enrollment_catalog=Catalog(), build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
        build_store=None, service_connector=None,
        selected_resource_execution_records=(row,), resource_backend_records=(backend,),
        resource_scope_binding_records=(scope,),
        protected_rules={(row["capability"], row["operation"], row["target_id"]):
                         SimpleNamespace(recipient=row["recipient"])},
    )
    selected = binding.resolve_selected_resource_record(
        row["resource_id"], resource_generation=row["resource_generation"],
        profile_id=row["profile_id"],
    )
    assert selected.resource_id == row["resource_id"] and selected.enabled is True
    assert selected.service_generation_digest == digest
    assert not hasattr(selected, "effective_spec")
    with pytest.raises(EnrollmentDenied, match="absent or ambiguous"):
        binding.resolve_selected_resource_record(
            row["resource_id"], resource_generation="6" * 64,
            profile_id=row["profile_id"],
        )


def test_selected_application_runtime_record_joins_recipe_roots_and_artifacts_but_is_not_a_receipt():
    digest = "a" * 64
    row = {
        "application_id": "application-a", "profile_id": "profile-a",
        "profile_generation": "profile-generation-a", "principal_id": "principal-a",
        "adapter_id": "adapter-a", "source_identity": "https://github.com/example/app",
        "source_revision": "1" * 40, "source_tree_sha256": "2" * 64,
        "source_generation_receipt_handle": "source-receipt-a",
        "source_generation_manifest_sha256": "3" * 64, "runtime_id": "runtime-a",
        "runtime_receipt_handle": "runtime-receipt-a", "runtime_manifest_sha256": "4" * 64,
        "lock_sha256": "5" * 64, "work_root_id": "work-a", "data_root_id": "data-a",
        "operation_id": "application-run-v1", "process_start_target": "application:start",
        "request_schema_id": "request-schema-a", "request_schema_sha256": "6" * 64,
        "result_schema_id": "result-schema-a", "result_validator_artifact_id": "result-validator-a",
        "result_validator_sha256": "7" * 64, "capability_ids": ("application:run",),
        "provider_route_ids": (), "credential_reference_ids": (),
        "account_eligibility_receipt_handle": None, "memory_owner_generation": None,
        "max_lifetime_seconds": 60, "max_memory_bytes": 1024 * 1024,
        "max_workers": 1, "metered_budget_usd": 0, "enabled": False,
    }
    service = SimpleNamespace(
        profile_id="profile-a", generation="profile-generation-a", enrollment_id="service-a",
        principal_id="principal-a", service_uid=1001, service_gid=1001,
        roots=SimpleNamespace(work_id="work-a", data_id="data-a"),
    )
    class Catalog:
        def __init__(self):
            self.digest = digest
        def resolve_profile_generation(self, profile_id, generation):
            assert (profile_id, generation) == ("profile-a", "profile-generation-a")
            return service
        def resolve_launch_recipe(self, enrollment_id, generation, operation_id):
            assert (enrollment_id, generation, operation_id) == (
                "service-a", "profile-generation-a", "application-run-v1")
            return SimpleNamespace(process_start_target="application:start",
                                   recipe=SimpleNamespace(max_lifetime_seconds=90))
        def resolve_operation(self, enrollment_id, generation, operation):
            assert operation == "process.start"
            return SimpleNamespace(target="application:start")

    binding = RootRuntimeBindings(
        enrollment_catalog=Catalog(), build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={},
        artifact_catalog=SimpleNamespace(artifacts={
            "request-schema-a": SimpleNamespace(sha256="6" * 64),
            "result-validator-a": SimpleNamespace(sha256="7" * 64),
        }), build_store=None, service_connector=None,
        process_profiles={"profile-a": SimpleNamespace(
            enrollment_id="service-a", generation="profile-generation-a",
            owner_uid=1001, owner_gid=1001, max_lifetime_seconds=90,
            memory_max_bytes=2 * 1024 * 1024)},
        selected_application_runtime_records=(row,),
    )
    selected = binding.resolve_selected_application_runtime_record("application-a", profile_id="profile-a")
    assert selected.application_id == "application-a"
    assert selected.service_generation_digest == digest
    assert not hasattr(selected, "effective_spec")
    # The protected row is only a selector. Even an otherwise valid enabled
    # row cannot become an executable DTO until current source and runtime
    # receipts are resolved from retained root registries.
    row["enabled"] = True
    with pytest.raises(EnrollmentDenied, match="receipt registries are unavailable"):
        binding.resolve_selected_application_runtime("application-a", "profile-a")
    with pytest.raises(EnrollmentDenied, match="absent or ambiguous"):
        binding.resolve_selected_application_runtime_record("application-a", profile_id="other-profile")


def test_build_process_profile_resolves_only_service_joined_to_fixed_build_target():
    service = SimpleNamespace(profile_id="build-profile", enrollment_id="build-enrollment",
                               generation="service-gen", service_uid=2001, service_gid=2002)
    custody = SimpleNamespace(
        profile_id="build-profile", enrollment_id="build-enrollment", generation="service-gen",
        owner_uid=2001, owner_gid=2002, operation_targets={"process.start": "coral-cpython-build:start"},
    )
    build_profile = SimpleNamespace(output_owner_uid=2001)

    class Builds:
        def resolve_service(self, target, generation, catalog):
            assert target == "coral-cpython-build:start" and generation == "build-gen"
            assert catalog is bindings.enrollment_catalog
            return build_profile, service

    bindings = RootRuntimeBindings(
        enrollment_catalog=object(), build_catalog=Builds(), device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
        build_store=None, service_connector=None,
        process_profiles={"build-profile": custody},
    )
    assert bindings.resolve_build_process_profile(
        "coral-cpython-build:start", "build-gen") is custody
    custody.owner_uid = 9999
    with pytest.raises(EnrollmentDenied, match="dedicated build process custody"):
        bindings.resolve_build_process_profile("coral-cpython-build:start", "build-gen")


def test_selected_native_principal_returns_only_unique_current_protected_binding():
    from hermes_installer.authority.service import PrincipalBinding

    service = SimpleNamespace(
        profile_id="desktop-profile", generation="desktop-generation",
        enrollment_id="desktop-enrollment", service_uid=2201, service_gid=2202,
        principal_id="desktop-principal", namespace_identity="mnt:11;net:12",
    )
    binding = PrincipalBinding(
        uid=2201, principal_id="desktop-principal", profile_id="desktop-profile",
        namespace_id="mnt:11;net:12", capabilities=frozenset({"remote.desktop"}),
    )

    class Catalog:
        digest = "d" * 64

        def resolve_profile_generation(self, profile_id, generation):
            if profile_id != service.profile_id or generation != service.generation:
                raise EnrollmentDenied("stale selection")
            return service

    custody = SimpleNamespace(
        profile_id=service.profile_id, generation=service.generation,
        enrollment_id=service.enrollment_id, owner_uid=service.service_uid,
        owner_gid=service.service_gid,
    )
    runtime = RootRuntimeBindings(
        enrollment_catalog=Catalog(), build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
        build_store=None, service_connector=None,
        process_profiles={service.profile_id: custody},
        protected_principal_bindings=(binding,),
    )
    assert runtime.resolve_selected_native_principal(
        service.profile_id, service.generation, "d" * 64,
    ) is binding

    for stale_generation, digest in (("old-generation", "d" * 64),
                                     (service.generation, "e" * 64)):
        with pytest.raises(EnrollmentDenied):
            runtime.resolve_selected_native_principal(service.profile_id, stale_generation, digest)

    duplicate = RootRuntimeBindings(
        enrollment_catalog=runtime.enrollment_catalog, build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
        build_store=None, service_connector=None, process_profiles=runtime.process_profiles,
        protected_principal_bindings=(binding, binding),
    )
    with pytest.raises(EnrollmentDenied, match="absent or ambiguous"):
        duplicate.resolve_selected_native_principal(
            service.profile_id, service.generation, "d" * 64,
        )

    wrong_uid = PrincipalBinding(
        uid=2203, principal_id="desktop-principal", profile_id="desktop-profile",
        namespace_id="mnt:11;net:12", capabilities=frozenset({"remote.desktop"}),
    )
    mismatched = RootRuntimeBindings(
        enrollment_catalog=runtime.enrollment_catalog, build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
        build_store=None, service_connector=None, process_profiles=runtime.process_profiles,
        protected_principal_bindings=(wrong_uid,),
    )
    with pytest.raises(EnrollmentDenied, match="UID and namespace"):
        mismatched.resolve_selected_native_principal(
            service.profile_id, service.generation, "d" * 64,
        )


def test_selected_gateway_boundary_joins_current_kernel_proof_and_pinned_remote_row():
    profile = SimpleNamespace(profile_id="gateway-profile", generation="gateway-generation",
                              enrollment_id="gateway-enrollment", owner_uid=2301)
    proof = SimpleNamespace(
        profile_id="gateway-profile", profile_generation="gateway-generation",
        enrollment_id="gateway-enrollment", uid=2301, gid=2301, pid=321,
        pid_starttime_ticks=456, executable_device=12, executable_inode=34,
        executable_sha256="a" * 64, cgroup_id="/system.slice/gateway.service",
        mount_namespace_inode=56, network_namespace_inode=78,
    )
    manager = SimpleNamespace(inspect_enrolled_process=lambda pid, generation: proof)
    runtime = RootRuntimeBindings(
        enrollment_catalog=SimpleNamespace(digest="d" * 64), build_catalog=None,
        device_catalog=None, process_manager=manager, effect_handlers={}, native_bridges={},
        artifact_catalog=None, build_store=None, service_connector=None,
        process_profiles={"gateway-profile": profile},
        remote_observation_records=({"remote_enrollment_id": "remote-a",
                                     "gateway_listener_port": 8743},),
        remote_session_records=({"id": "remote-a", "gateway_profile_id": "gateway-profile",
                                 "gateway_role_sha256": "a" * 64, "expected_hostname": "chat.example",
                                 "policy_config_digest": "b" * 64, "policy_revision": "rev-a"},),
    )
    selected = runtime.selected_gateway_boundary("remote-a")
    assert (selected.gateway_profile_id, selected.gateway_generation, selected.listener_port) == (
        "gateway-profile", "gateway-generation", 8743)
    assert selected.gateway_identity_digest != "a" * 64
    proof.executable_sha256 = "c" * 64
    with pytest.raises(EnrollmentDenied, match="current matching custody role proof"):
        runtime.selected_gateway_boundary("remote-a")


def test_selected_native_window_fails_closed_without_current_process_binding():
    runtime = RootRuntimeBindings(
        enrollment_catalog=None, build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
        build_store=None, service_connector=None,
        remote_observation_records=({"remote_enrollment_id": "remote-a"},),
        remote_session_records=({"id": "remote-a"},),
    )
    with pytest.raises(EnrollmentDenied, match="process binding is incomplete"):
        runtime.selected_native_window("remote-a")


def test_native_mcp_selection_requires_current_native_adapter_scope_and_effect_rule():
    service = SimpleNamespace(profile_id="profile-a", generation="generation-a",
                              enrollment_id="enrollment-a")
    action = SimpleNamespace(
        action_id="binding-a", generation="generation-a",
        adapter_artifact_id="handler-a", adapter_sha256="a" * 64,
        adapter_id="hermes-installer.native-mcp-dispatch.v1",
        operation="mcp.request", target_id="mcp:mcp-a:http",
        capability="mcp:mcp-a:read", recipient=None,
    )
    registration = SimpleNamespace(
        handler_kind="mcp-dispatch", handler_id="binding-a",
        native_tool_name="query", native_server_name="hermes-installer",
    )
    package = SimpleNamespace(
        profile_id="profile-a", generation="generation-a", profile_generation="generation-a",
        action_records={"action-a": action}, registration_records={"registration-a": registration},
    )

    class Catalog:
        digest = "d" * 64

        def resolve_profile_generation(self, profile_id, generation):
            if (profile_id, generation) != ("profile-a", "generation-a"):
                raise EnrollmentDenied("stale")
            return service

        def resolve_native_package(self, package_id, generation):
            assert (package_id, generation) == ("package-a", "generation-a")
            return package

    row = {
        "id": "binding-a", "profile_id": "profile-a", "process_generation": "generation-a",
        "native_package_id": "package-a", "native_package_generation": "generation-a",
        "native_tool_name": "query", "native_server_name": "hermes-installer",
        "mcp_enrollment_id": "mcp-a", "mcp_tool_name": "search",
        "effect_operation": "mcp.request", "effect_target": "mcp:mcp-a:http",
        "capability": "mcp:mcp-a:read", "recipient": None,
        "scope_bindings": ({"argument_field": "resource", "selected_resource_id": "resource-a"},),
        "handler_artifact_id": "handler-a", "handler_artifact_sha256": "a" * 64,
    }
    custody = SimpleNamespace(profile_id="profile-a", generation="generation-a",
                              enrollment_id="enrollment-a")
    rules = {("mcp:mcp-a:read", "mcp.request", "mcp:mcp-a:http"): object()}
    runtime = RootRuntimeBindings(
        enrollment_catalog=Catalog(), build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
        build_store=None, service_connector=None, process_profiles={"profile-a": custody},
        native_mcp_tool_binding_records=(row,),
        mcp_services={"mcp-a": {"id": "mcp-a", "channel": "http",
                                 "allowed_tools": ["search"],
                                 "selection_arguments": {"search": ["resource"]}}},
        protected_rules=rules,
    )
    assert runtime.resolve_native_mcp_tool_bindings(
        "profile-a", "generation-a", "d" * 64) == (row,)
    rules.clear()
    with pytest.raises(EnrollmentDenied, match="exact selected authority rule"):
        runtime.resolve_native_mcp_tool_bindings("profile-a", "generation-a", "d" * 64)


def test_resource_credential_placeholder_resolves_only_after_backend_profile_and_observer_join():
    from hermes_installer.authority.runtime_bindings import _derive_resource_credential_bindings

    row = {
        "id": "backend-a", "resource_id": "resource-a", "profile_id": "profile-a",
        "principal_id": "principal-a", "generation": "resource-generation-a",
        "profile_generation": "profile-generation-a", "observer_enrollment_id": "observer-a",
        "credential_reference_ids": ["vault-reference-a"],
        "credential_bindings": [{"source_placeholder": "${API_KEY}",
                                  "credential_reference_id": "vault-reference-a",
                                  "usage": "backend-account"}],
    }
    derived = _derive_resource_credential_bindings(SimpleNamespace(
        resource_backend_enrollment_records=(row,),
    ))
    service = SimpleNamespace(profile_id="profile-a", generation="profile-generation-a")
    issuer = SimpleNamespace(observer_enrollment_id="observer-a")
    package = SimpleNamespace(profile_id="profile-a", profile_generation="profile-generation-a",
                              generation="package-generation-a")
    join = SimpleNamespace(issuer=issuer, package=package)

    class Catalog:
        digest = "d" * 64
        source_observer_joins = {"observer-a": join}

        def resolve_profile_generation(self, profile_id, generation):
            if (profile_id, generation) != ("profile-a", "profile-generation-a"):
                raise EnrollmentDenied("stale profile")
            return service

    runtime = RootRuntimeBindings(
        enrollment_catalog=Catalog(), build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
        build_store=None, service_connector=None, resource_credential_bindings=derived,
    )
    binding = runtime.resolve_resource_credential_binding(
        "backend-a", "${API_KEY}", "backend-account", profile_id="profile-a",
        profile_generation="profile-generation-a", resource_id="resource-a",
        resource_generation="resource-generation-a", observer_enrollment_id="observer-a",
        service_generation_digest="d" * 64,
    )
    assert binding.credential_reference_id == "vault-reference-a"
    with pytest.raises(EnrollmentDenied, match="does not match its current protected backend"):
        runtime.resolve_resource_credential_binding(
            "backend-a", "${API_KEY}", "channel-account", profile_id="profile-a",
            profile_generation="profile-generation-a", resource_id="resource-a",
            resource_generation="resource-generation-a", observer_enrollment_id="observer-a",
            service_generation_digest="d" * 64,
        )


def test_resource_controller_role_requires_current_digest_observer_backend_and_artifact_pins():
    role = {
        "id": "controller-a", "source_observer_enrollment_ids": ["observer-a"],
        "allowed_backend_enrollment_ids": ["backend-a"],
        "daemon_executable_artifact_id": "daemon-a", "daemon_executable_sha256": "a" * 64,
        "role_module_artifact_id": "module-a", "role_module_sha256": "b" * 64,
    }
    issuer = SimpleNamespace(observer_enrollment_id="observer-a")

    class Catalog:
        digest = "d" * 64
        source_issuers = (issuer,)

    runtime = RootRuntimeBindings(
        enrollment_catalog=Catalog(), build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={},
        artifact_catalog=SimpleNamespace(artifacts={
            "daemon-a": SimpleNamespace(sha256="a" * 64),
            "module-a": SimpleNamespace(sha256="b" * 64),
        }), build_store=None, service_connector=None,
        resource_controller_role_records=(role,),
        resource_backend_records=({"id": "backend-a"},),
    )
    assert runtime.resolve_resource_controller_role("controller-a", "d" * 64)["id"] == "controller-a"
    with pytest.raises(EnrollmentDenied, match="stale service generation"):
        runtime.resolve_resource_controller_role("controller-a", "e" * 64)
    runtime.artifact_catalog.artifacts["module-a"] = SimpleNamespace(sha256="c" * 64)
    with pytest.raises(EnrollmentDenied, match="artifact does not match"):
        runtime.resolve_resource_controller_role("controller-a", "d" * 64)


def test_native_schema_record_selection_joins_protected_package_action_and_kind():
    from hermes_installer.protected_enrollment import EnrollmentDenied

    adapter = SimpleNamespace(
        adapter_id="adapter-a", action_id="action-a",
        argument_schema_id="direct-arguments-v1", result_schema_id="direct-result-v1",
        adapter_artifact_id="adapter-artifact-a", adapter_sha256="b" * 64,
        workflow_bindings=({
            "external_tool_name": "lookup", "external_action_id": "external-lookup",
            "external_argument_schema_id": "workflow-arguments-v1",
            "external_result_schema_id": "workflow-result-v1",
            "workflow_artifact_id": "workflow-artifact-a", "workflow_sha256": "f" * 64,
        },),
    )
    package = SimpleNamespace(
        profile_id="profile-a", profile_generation="process-generation-a",
        action_records={"adapter-a:action:action-a": SimpleNamespace(
            adapter_id="adapter-a", action_id="action-a",
            argument_schema_id="direct-arguments-v1", result_schema_id="direct-result-v1",
            adapter_artifact_id="adapter-artifact-a", adapter_sha256="b" * 64,
        )},
        registration_records={"adapter-a:tool:lookup": SimpleNamespace(
            adapter_id="adapter-a", registration_id="adapter-a:tool:lookup",
            registration_source_artifact_id="registration-artifact-a",
            registration_source_sha256="e" * 64,
            action_bindings=(SimpleNamespace(workflow_id="workflow-a"),),
        )},
        workflow_records={"workflow-a": SimpleNamespace(
            workflow_id="workflow-a", registration_id="adapter-a:tool:lookup",
            external_argument_schema_id="workflow-arguments-v1",
            external_result_schema_id="workflow-result-v1",
            workflow_artifact_id="workflow-artifact-a", workflow_sha256="f" * 64,
        )},
        process_role_records={},
        entrypoint_artifact_id="entrypoint-a", entrypoint_sha256="c" * 64,
        resolver_artifact_id="resolver-a", resolver_sha256="d" * 64,
        compiled_closure_artifact_id="closure-a",
    )
    row = {
        "id": "workflow-arguments-v1", "artifact_id": "schema-arguments-v1", "sha256": "a" * 64,
        "schema_kind": "arguments", "native_package_id": "package-a",
        "native_package_generation": "generation-a", "adapter_id": "adapter-a",
        "action_id": "action-a", "source_receipt_handle": "receipt-a",
        "size_bytes": 123, "derivation_receipt_handle": None,
    }

    class Catalog:
        def resolve_native_package(self, package_id, generation):
            if (package_id, generation) != ("package-a", "generation-a"):
                raise EnrollmentDenied("package generation unavailable")
            return package

    artifact_specs = {
        "closure-a": SimpleNamespace(tree_files=(object(),)),
        "entrypoint-a": SimpleNamespace(sha256="c" * 64),
        "resolver-a": SimpleNamespace(sha256="d" * 64),
        "adapter-artifact-a": SimpleNamespace(sha256="b" * 64),
        "workflow-artifact-a": SimpleNamespace(sha256="f" * 64),
        "registration-artifact-a": SimpleNamespace(sha256="e" * 64),
    }

    runtime = RootRuntimeBindings(
        enrollment_catalog=Catalog(), build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={},
        artifact_catalog=SimpleNamespace(artifacts=artifact_specs),
        build_store=None, service_connector=None, native_schema_artifact_records=(row,),
    )
    assert runtime.resolve_native_schema_record(
        "workflow-arguments-v1", "package-a", "generation-a", "adapter-a", "action-a", "arguments",
    ) is row
    package.workflow_records["workflow-b"] = SimpleNamespace(
        workflow_id="workflow-b", registration_id="adapter-a:tool:lookup",
        external_argument_schema_id="workflow-arguments-v1",
        external_result_schema_id="workflow-result-v1",
        workflow_artifact_id="workflow-artifact-b", workflow_sha256="1" * 64,
    )
    package.registration_records["adapter-a:tool:lookup"].action_bindings += (
        SimpleNamespace(workflow_id="workflow-b"),
    )
    artifact_specs["workflow-artifact-b"] = SimpleNamespace(sha256="1" * 64)
    with pytest.raises(EnrollmentDenied, match="ambiguous across selected external actions"):
        runtime.resolve_native_schema_record(
            "workflow-arguments-v1", "package-a", "generation-a", "adapter-a", "action-a", "arguments",
        )
    with pytest.raises(EnrollmentDenied, match="not selected"):
        runtime.resolve_native_schema_record(
            "workflow-result-v1", "package-a", "generation-a", "adapter-a", "action-a", "arguments",
        )
    with pytest.raises(EnrollmentDenied, match="not selected"):
        runtime.resolve_native_schema_record(
            "workflow-arguments-v1", "package-a", "generation-a", "adapter-a", "action-a", "result",
        )


def test_composio_channel_selection_joins_active_resource_controller_and_observer():
    from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
    from hermes_installer.protected_enrollment import EnrollmentDenied

    row = {"id": "channel-a", "channel_resource_id": "resource-a",
           "resource_generation": "resource-generation-a", "profile_id": "profile-a",
           "controller_role_id": "controller-a", "source_issuer_id": "observer-a",
           "composio_enrollment_id": "composio-a", "composio_user_id": "user-a",
           "connected_account_id": "account-a", "auth_config_id": "auth-a",
           "toolkit_version": "20260721_00", "trigger_artifact_id": "trigger-a",
           "trigger_artifact_sha256": "a" * 64, "trigger_slug": "messages.received",
           "trigger_instance_id": "instance-a", "webhook_subscription_id": "subscription-a",
           "webhook_route_enrollment_id": "route-a", "webhook_secret_reference_id": "secret-a",
           "allowed_user_numbers": ("+14155550123",),
           "payload_field_bindings": {key: (key,) for key in
                                       ("sender_number", "message_id", "message_text", "event_timestamp")},
           "max_event_age_seconds": 120, "account_receipt_handle": "account-receipt-a",
           "setup_receipt_handle": "setup-receipt-a"}
    observer = SimpleNamespace(profile_id="profile-a", generation="process-generation-a")
    runtime = RootRuntimeBindings(
        enrollment_catalog=None, build_catalog=None, device_catalog=None, process_manager=None,
        effect_handlers={}, native_bridges={}, artifact_catalog=None, build_store=None,
        service_connector=None, process_profiles={"profile-a": SimpleNamespace(generation="process-generation-a")},
        source_observer_enrollments={"observer-a": observer},
        composio_channel_enrollment_records=(row,),
        resource_job_records=({"resource_id": "resource-a", "generation": "resource-generation-a",
                               "profile_id": "profile-a"},),
        resource_controller_role_records=({"id": "controller-a", "controller_kind": "root-channel",
                                           "source_observer_enrollment_ids": ("observer-a",)},),
    )
    assert runtime.resolve_composio_channel_enrollment("channel-a", "resource-generation-a") is row
    with pytest.raises(EnrollmentDenied, match="absent or ambiguous"):
        runtime.resolve_composio_channel_enrollment("channel-a", "stale-resource-generation")


def test_native_window_getter_exposes_only_selected_identity_and_opaque_receipt():
    from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
    from hermes_installer.protected_enrollment import EnrollmentDenied

    native = SimpleNamespace(profile_id="desktop-profile", generation="desktop-generation",
                             enrollment_id="desktop-enrollment")
    display = SimpleNamespace(profile_id="display-profile", generation="display-generation",
                              enrollment_id="display-enrollment")
    runtime = RootRuntimeBindings(
        enrollment_catalog=None, build_catalog=None, device_catalog=None, process_manager=None,
        effect_handlers={}, native_bridges={}, artifact_catalog=None, build_store=None,
        service_connector=None, process_profiles={"desktop-profile": native, "display-profile": display},
        remote_session_records=({"id": "remote-a", "native_desktop_profile_id": "desktop-profile",
                                 "native_generation": "desktop-generation"},),
        remote_observation_records=({"remote_enrollment_id": "remote-a",
                                     "native_window_enrollment_id": "desktop-enrollment",
                                     "display_server_profile_id": "display-profile",
                                     "display_server_generation": "display-generation",
                                     "display_name": ":0", "xauthority_receipt_handle": "xauth-receipt-a"},),
    )
    selected = runtime.selected_native_window("remote-a")
    assert selected.xauthority_receipt_handle == "xauth-receipt-a"
    assert selected.display_name == ":0"
    assert not hasattr(selected, "xauthority_path")
    runtime.process_profiles["display-profile"] = SimpleNamespace(
        profile_id="display-profile", generation="stale", enrollment_id="display-enrollment",
    )
    with pytest.raises(EnrollmentDenied, match="stale process profile"):
        runtime.selected_native_window("remote-a")


def test_root_native_package_resolver_rejects_ambiguous_selected_profile_generation():
    from hermes_installer.authority.runtime_bindings import _build_native_package_resolver

    enrollment = SimpleNamespace(native_package_records=[
        {"profile_id": "profile-a", "profile_generation": "generation-a",
         "generation": "package-generation-a", "package_id": "package-a"},
        {"profile_id": "profile-a", "profile_generation": "generation-a",
         "generation": "package-generation-b", "package_id": "package-b"},
    ], source_issuers=())
    resolver = _build_native_package_resolver(
        enrollment=enrollment, catalog=None, artifact_catalog=None,
        staging_root="/unused", expected_uid=0,
    )
    with pytest.raises(EnrollmentDenied, match="ambiguous native packages"):
        resolver("profile-a", "generation-a")


def test_root_native_source_issuer_requires_selected_package_closure():
    from hermes_installer.authority.enrollment import SourceIssuerRecord
    from hermes_installer.authority.runtime_bindings import _build_native_package_resolver

    enrollment = SimpleNamespace(native_package_records=[], source_issuers=(SourceIssuerRecord(
        issuer_channel_id="native-input", producer_profile_id="profile-a",
        producer_role_artifact_id="role-a", producer_role_sha256="a" * 64,
        capture_schema_id="capture-a", allowed_parent_channels=(),
        generation="generation-a", observer_enrollment_id="observer-a",
        source_action_ids=("authenticated-input",),
    ),))
    resolver = _build_native_package_resolver(
        enrollment=enrollment, catalog=None, artifact_catalog=None,
        staging_root="/unused", expected_uid=0,
    )
    with pytest.raises(EnrollmentDenied, match="no selected native package closure"):
        resolver("profile-a", "generation-a")


def test_native_source_observer_stays_unavailable_without_protected_process_role_join():
    from hermes_installer.authority.runtime_bindings import _derive_source_observer_enrollments

    catalog = SimpleNamespace(source_observer_joins={})
    result = _derive_source_observer_enrollments(
        catalog=catalog, process_profiles={}, artifact_catalog=SimpleNamespace(artifacts={}),
    )
    assert result == {}


def test_native_source_observer_derives_process_role_separately_from_action_adapter():
    from hermes_installer.authority.runtime_bindings import _derive_source_observer_enrollments

    action = SimpleNamespace(
        action_id="authenticated-input", action_binding_id="adapter:binding:input",
        operation="native.input.capture", capability="native-input",
        target_id="target-input", recipient="local-private", generation="package-generation",
        observer_enrollment_ids=("observer-input",), adapter_artifact_id="action-adapter",
        adapter_sha256="a" * 64, argument_schema_id="input-v1", result_schema_id="output-v1",
        effect_enrollment_id="effect-input",
    )
    package = SimpleNamespace(
        package_id="package-input", profile_id="profile-input", profile_generation="process-generation",
        generation="package-generation", compiled_closure_sha256="b" * 64,
    )
    role = SimpleNamespace(
        role_id="role-input", role_artifact_id="process-role-module", role_sha256="c" * 64,
        package_id="package-input", native_package_generation="package-generation",
        profile_id="profile-input", profile_generation="process-generation",
        role_source_receipt_handle="role-source", module_name="hermes_installer.runtime.input_role",
        closure_member_path="roles/input_role.py", role_source_revision="source-rev",
        role_source_tree_sha256="d" * 64, action_binding_ids=(action.action_binding_id,),
    )
    issuer = SimpleNamespace(
        issuer_channel_id="native-input", producer_profile_id="profile-input",
        generation="process-generation", allowed_parent_channels=(), capture_schema_id="input-v1",
        source_action_ids=("authenticated-input",), private_provider_route_ids=(),
    )
    join = SimpleNamespace(issuer=issuer, package=package, process_role=role,
                           actions={action.action_binding_id: action})
    service = SimpleNamespace(
        profile_id="profile-input", principal_id="principal-input", namespace_identity="ns-input",
        enrollment_id="enrollment-input", service_uid=1200, executable_sha256="e" * 64,
    )
    catalog = SimpleNamespace(
        source_observer_joins={"observer-input": join},
        resolve_profile_generation=lambda _profile, _generation: service,
    )
    artifact_catalog = SimpleNamespace(artifacts={
        "process-role-module": SimpleNamespace(sha256="c" * 64),
    })

    result = _derive_source_observer_enrollments(
        catalog=catalog, process_profiles={}, artifact_catalog=artifact_catalog,
    )

    observer = result["observer-input"]
    assert observer.role_artifact_id == "process-role-module"
    assert observer.role_sha256 == "c" * 64
    assert observer.role_artifact_id != action.adapter_artifact_id
    assert observer.source_action_binding_id == action.action_binding_id
    assert observer.generation == "process-generation"
    assert observer.native_package_generation == "package-generation"


def test_native_source_observer_rejects_ambiguous_process_role_actions():
    from hermes_installer.authority.runtime_bindings import _derive_source_observer_enrollments

    action = SimpleNamespace(
        action_id="authenticated-input", action_binding_id="adapter:binding:input",
        operation="native.input.capture", capability="native-input", target_id="target-input",
        recipient="local-private", generation="package-generation",
        observer_enrollment_ids=("observer-input",),
    )
    duplicate = SimpleNamespace(**{**vars(action), "action_binding_id": "adapter:binding:other"})
    package = SimpleNamespace(
        package_id="package-input", profile_id="profile-input", profile_generation="process-generation",
        generation="package-generation", compiled_closure_sha256="b" * 64,
    )
    role = SimpleNamespace(
        role_id="role-input", role_artifact_id="process-role-module", role_sha256="c" * 64,
        package_id="package-input", native_package_generation="package-generation",
        profile_id="profile-input", profile_generation="process-generation",
        action_binding_ids=(action.action_binding_id, duplicate.action_binding_id),
    )
    issuer = SimpleNamespace(
        issuer_channel_id="native-input", producer_profile_id="profile-input",
        generation="process-generation", allowed_parent_channels=(), capture_schema_id="input-v1",
        source_action_ids=("authenticated-input",), private_provider_route_ids=(),
    )
    join = SimpleNamespace(issuer=issuer, package=package, process_role=role,
                           actions={action.action_binding_id: action,
                                    duplicate.action_binding_id: duplicate})
    service = SimpleNamespace(
        profile_id="profile-input", principal_id="principal-input", namespace_identity="ns-input",
        enrollment_id="enrollment-input", service_uid=1200, executable_sha256="e" * 64,
    )
    catalog = SimpleNamespace(
        source_observer_joins={"observer-input": join},
        resolve_profile_generation=lambda _profile, _generation: service,
    )
    artifact_catalog = SimpleNamespace(artifacts={
        "process-role-module": SimpleNamespace(sha256="c" * 64),
    })

    with pytest.raises(EnrollmentDenied, match="one exact process-role action binding"):
        _derive_source_observer_enrollments(
            catalog=catalog, process_profiles={}, artifact_catalog=artifact_catalog,
        )


def test_root_native_package_materializer_uses_only_protected_artifact_references(tmp_path):
    import json
    from hermes_installer.authority.runtime_bindings import _build_native_package_resolver

    class ArtifactCatalog:
        def __init__(self):
            self.artifacts = {"closure-a": SimpleNamespace(sha256="a" * 64, tree_files=(object(),))}
            self.calls = []
            self.manifest_path = tmp_path / "native-manifest.json"
            self.manifest_path.write_text(json.dumps({
                "schema": 1, "package_id": "package-a", "profile_id": "profile-a",
                    "generation": "native-generation-a", "closure_files": [], "adapters": [],
                "dependencies": [],
            }), encoding="utf-8")

        def materialize_tree(self, artifact_id, sha256, root, *, expected_uid):
            self.calls.append(("tree", artifact_id, sha256, root, expected_uid))
            return SimpleNamespace(artifact_id=artifact_id, sha256=sha256, path=tmp_path / "closure")

        def resolve(self, artifact_id, sha256, root, *, expected_uid):
            self.calls.append(("file", artifact_id, sha256, root, expected_uid))
            path = self.manifest_path if artifact_id == "entrypoint-a" else tmp_path / "resolver.py"
            if path.name == "resolver.py":
                path.write_text("# pinned", encoding="utf-8")
            return SimpleNamespace(artifact_id=artifact_id, sha256=sha256, path=path)

    package = SimpleNamespace(
        package_id="package-a", profile_id="profile-a", generation="native-generation-a",
        profile_generation="generation-a",
        compiled_closure_artifact_id="closure-a", compiled_closure_sha256="b" * 64,
        entrypoint_artifact_id="entrypoint-a", entrypoint_sha256="c" * 64,
        resolver_artifact_id="resolver-a", resolver_sha256="d" * 64,
        adapter_records={}, action_records={}, registration_records={}, workflow_records={},
    )
    catalog = SimpleNamespace(resolve_native_package=lambda package_id, generation: package)
    artifact_catalog = ArtifactCatalog()
    enrollment = SimpleNamespace(native_package_records=[{
        "package_id": "package-a", "profile_id": "profile-a", "generation": "native-generation-a",
        "profile_generation": "generation-a",
    }], source_issuers=())
    resolver = _build_native_package_resolver(
        enrollment=enrollment, catalog=catalog, artifact_catalog=artifact_catalog,
        staging_root=tmp_path, expected_uid=0,
    )
    selected = resolver("profile-a", "generation-a")
    assert selected.binding.package_id == "package-a"
    assert selected.profile_id == "profile-a"
    assert [call[:3] for call in artifact_catalog.calls] == [
        ("tree", "closure-a", "a" * 64),
        ("file", "entrypoint-a", "c" * 64),
        ("file", "resolver-a", "d" * 64),
    ]


def test_package_set_manifest_may_be_absent_but_malformed_manifest_still_denies(tmp_path, monkeypatch):
    import os
    from hermes_installer import artifacts
    from hermes_installer.authority.runtime_bindings import _load_optional_package_sets

    manifest = tmp_path / "package-sets.json"
    tmp_path.chmod(0o700)
    monkeypatch.setattr(artifacts, "PACKAGE_SET_MANIFEST_PATH", manifest)
    result = _load_optional_package_sets(
        catalog=None, signing_key=b"k" * 32, key_id="test-key", expected_uid=os.getuid(),
    )
    assert dict(result) == {}

    manifest.write_text("{}", encoding="utf-8")
    manifest.chmod(0o600)
    with pytest.raises(AuthorityDenied) as caught:
        _load_optional_package_sets(
            catalog=None, signing_key=b"k" * 32, key_id="test-key", expected_uid=os.getuid(),
        )
    assert caught.value.code == "package-set.catalog"


def test_package_set_manifest_symlink_is_not_treated_as_absent(tmp_path, monkeypatch):
    import os
    from hermes_installer import artifacts
    from hermes_installer.authority.runtime_bindings import _load_optional_package_sets

    tmp_path.chmod(0o700)
    target = tmp_path / "target.json"
    target.write_text('{"schema":1,"package_sets":[]}', encoding="utf-8")
    target.chmod(0o600)
    manifest = tmp_path / "package-sets.json"
    manifest.symlink_to(target)
    monkeypatch.setattr(artifacts, "PACKAGE_SET_MANIFEST_PATH", manifest)
    with pytest.raises(AuthorityDenied):
        _load_optional_package_sets(
            catalog=None, signing_key=b"k" * 32, key_id="test-key", expected_uid=os.getuid(),
        )
