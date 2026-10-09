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
    )
    with pytest.raises(EnrollmentDenied, match="service generation records"):
        build_root_runtime_bindings(
            enrollment, vault=None, artifact_catalog=None,
            authorization_check=lambda **_: True,
        )


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


def test_selected_native_window_fails_closed_without_root_xauthority_receipt_resolver():
    runtime = RootRuntimeBindings(
        enrollment_catalog=None, build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
        build_store=None, service_connector=None,
        remote_observation_records=({"remote_enrollment_id": "remote-a"},),
        remote_session_records=({"id": "remote-a"},),
    )
    with pytest.raises(EnrollmentDenied, match="no installed Xauthority startup receipt resolver"):
        runtime.selected_native_window("remote-a")


def test_native_mcp_selection_requires_current_native_adapter_scope_and_effect_rule():
    service = SimpleNamespace(profile_id="profile-a", generation="generation-a",
                              enrollment_id="enrollment-a")
    adapter = SimpleNamespace(
        action_id="binding-a", generation="generation-a",
        adapter_artifact_id="handler-a", adapter_sha256="a" * 64,
    )
    package = SimpleNamespace(
        profile_id="profile-a", generation="generation-a",
        adapter_records={"hermes-installer.native-mcp-dispatch.v1": adapter},
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
    package = SimpleNamespace(profile_id="profile-a", generation="profile-generation-a")
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


def test_root_native_package_resolver_rejects_ambiguous_selected_profile_generation():
    from hermes_installer.authority.runtime_bindings import _build_native_package_resolver

    enrollment = SimpleNamespace(native_package_records=[
        {"profile_id": "profile-a", "generation": "generation-a", "package_id": "package-a"},
        {"profile_id": "profile-a", "generation": "generation-a", "package_id": "package-b"},
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


def test_native_source_observer_metadata_derives_only_from_exact_active_join():
    from hermes_installer.authority.enrollment import SourceIssuerRecord
    from hermes_installer.authority.runtime_bindings import _derive_source_observer_enrollments

    issuer = SourceIssuerRecord(
        "tool-result", "profile-a", "role-artifact", "a" * 64,
        "result-schema", (), "generation-a", "observer-a", ("registered-tool-result",),
    )
    adapter = SimpleNamespace(
        adapter_id="adapter-a", adapter_artifact_id="role-artifact", adapter_sha256="a" * 64,
        operation="plugin.example.read", target_id="target-a", recipient="recipient-a",
    )
    package = SimpleNamespace(
        package_id="package-a", profile_id="profile-a", generation="generation-a",
        compiled_closure_sha256="b" * 64, adapter_records={"adapter-a": adapter},
    )
    service = SimpleNamespace(
        profile_id="profile-a", principal_id="principal-a", namespace_identity="namespace-a",
        enrollment_id="service-a", generation="generation-a", service_uid=1001,
        executable_sha256="c" * 64,
    )
    join = SimpleNamespace(issuer=issuer, package=package, adapter=adapter)
    catalog = SimpleNamespace(
        source_observer_joins={"observer-a": join},
        resolve_profile_generation=lambda *_args: service,
    )
    artifacts = SimpleNamespace(artifacts={"role-artifact": SimpleNamespace(sha256="a" * 64)})
    result = _derive_source_observer_enrollments(
        catalog=catalog, process_profiles={}, artifact_catalog=artifacts,
    )
    selected = result["observer-a"]
    assert (selected.source_kind, selected.source_action_id, selected.role_id) == (
        "tool-result", "registered-tool-result", "adapter-a")
    assert (selected.producer_uid, selected.package_sha256, selected.recipient) == (
        1001, "b" * 64, "recipient-a")


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
                "generation": "generation-a", "closure_files": [], "adapters": [],
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
        package_id="package-a", profile_id="profile-a", generation="generation-a",
        compiled_closure_artifact_id="closure-a", compiled_closure_sha256="b" * 64,
        entrypoint_artifact_id="entrypoint-a", entrypoint_sha256="c" * 64,
        resolver_artifact_id="resolver-a", resolver_sha256="d" * 64,
        adapter_records={},
    )
    catalog = SimpleNamespace(resolve_native_package=lambda package_id, generation: package)
    artifact_catalog = ArtifactCatalog()
    enrollment = SimpleNamespace(native_package_records=[{
        "package_id": "package-a", "profile_id": "profile-a", "generation": "generation-a",
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
