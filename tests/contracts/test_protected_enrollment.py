from __future__ import annotations

import hashlib
import json
import stat
import copy
from types import SimpleNamespace
from pathlib import Path

import pytest

from hermes_installer.protected_enrollment import (
    EnrollmentDenied,
    FixedBuildProfile,
    OperationParameterSchema,
    NativePackageBinding,
    ProtectedBuildCatalog,
    ProtectedDeviceCatalog,
    ProtectedEnrollmentCatalog,
    ProtectedRootJournalCatalog,
    RootSelectedPublicWebScope,
    _canonical,
    _parse_profile,
)


def build_record(target="coral-cpython-build:start"):
    if target == "colibri-source-build:start":
        outputs = [{"relative_path": "c/colibri", "kind": "file", "maximum_bytes": 67108864,
                    "executable_role": "colibri-engine", "target_facts": {
                        "elf_class": 64, "elf_machine": "EM_AARCH64", "os": "linux",
                        "required_runtime_dependencies": ["libgomp.so.1", "libm", "libc"],
                        "instruction_policy": "actual target compatible ARM64 flags; no x86 default or unmeasured CPUflags",
                    }}]
    else:
        outputs = [
            {"relative_path": "runtime/bin/python3.9", "kind": "file", "maximum_bytes": 67108864,
             "executable_role": "coral-cpython39", "target_facts": {
                 "elf_class": 64, "elf_machine": "EM_AARCH64", "python_version": "3.9.25",
                 "soabi": "cpython-39-aarch64-linux-gnu", "debug": False,
                 "glibc_minimum": "2.34 for selected TFLite wheel",
             }},
            {"relative_path": "runtime/lib/python3.9", "kind": "tree", "maximum_bytes": 268435456,
             "executable_role": "cpython-stdlib-and-extension-closure", "target_facts": {
                 "python_version": "3.9.25", "target": "linux-aarch64",
                 "all_native_extensions": "ELF64EM_AARCH64, actual dependency closure verified",
             }},
        ]
    return {
        "target_id": target,
        "generation": "g1",
        "build_service_enrollment_id": "build-service-a",
        "build_service_generation": "build-service-generation-a",
        "source_artifact_id": "source-v1",
        "source_sha256": "1" * 64,
        "toolchain_artifact_id": "toolchain-v1",
        "toolchain_sha256": "2" * 64,
        "builder_artifact_id": "builder-v1",
        "builder_sha256": "3" * 64,
        "argv_recipe": [
            {"build_path": {"mount_id": "builder", "relative_path": ""}},
            {"literal": "--profile"}, {"literal": "coral-cpython-build"},
        ],
        "environment": {"PATH": "/opt/hermes/bin", "LANG": "C.UTF-8"},
        "max_lifetime_seconds": 600,
        "output_root_id": "coral-build-staging",
        "output_root": "/var/lib/hermes-installer/builds/coral",
        "output_owner_uid": 1001,
        "output_specs": outputs,
    }


def launch_recipe(root_id="data"):
    return {
        "executable_artifact_id": "runtime-v1", "executable_sha256": "a" * 64,
        "argv_recipe": [{"literal": "serve"}], "cwd_root_id": root_id, "cwd_subpath": "",
        "environment": {}, "child_artifact_refs": {}, "max_lifetime_seconds": 600,
        "max_output_bytes": 4096, "stdin_mode": "closed", "parameter_schema_id": "empty-params-v1",
    }


def test_build_target_is_fixed_and_generation_bound():
    catalog = ProtectedBuildCatalog.from_protected_records([
        build_record(), build_record("colibri-source-build:start"),
    ])
    assert catalog.resolve("coral-cpython-build:start", "g1").builder_sha256 == "3" * 64
    with pytest.raises(EnrollmentDenied):
        catalog.resolve("colibri-source-build:start", "g2")
    with pytest.raises(EnrollmentDenied):
        catalog.resolve("coral-cpython-build:start", "g2")
    with pytest.raises(EnrollmentDenied):
        catalog.resolve("/tmp/attacker-script", "g1")


def test_package_runtime_requires_signed_completed_build_receipt():
    profile = SimpleNamespace(
        enrollment_id="service-a", generation="gen-a",
        runtime_artifact_ids=("coral-python39-source",), service_uid=1001, service_gid=1001,
        profile_id="profile-a", principal_id="principal-a",
        package_runtime_records={"coral-cp39-runtime-v1": SimpleNamespace(
            runtime_artifact_id="coral-python39-source", abi="cp39/aarch64",
            target_glibc_min="2.34", build_target="coral-cpython-build:start",
            build_generation="gen-a", runtime_build_attestation_digest="b" * 64,
            runtime_executable_sha256="c" * 64, runtime_build_output="python/bin/python3.9",
            venv_root_id="venv-a", policy_revision="policy-a",
            runtime_executable=Path("/opt/hermes/python3.9"),
            venv_root=Path("/var/lib/hermes/venv-a"),
        )},
    )
    catalog = object.__new__(ProtectedEnrollmentCatalog)
    catalog.resolve = lambda *_args: profile
    build_catalog = SimpleNamespace(resolve=lambda *_args: SimpleNamespace(
        target_id="coral-cpython-build:start", generation="gen-a",
        attest_outputs=lambda: {"python/bin/python3.9": "c" * 64},
    ))
    with pytest.raises(EnrollmentDenied, match="completed root build attestation"):
        catalog.resolve_package_runtime(
            "service-a", "gen-a", "coral-cp39-runtime-v1", build_catalog,
            build_store=None,
        )


def test_selected_application_row_is_exposed_unchanged_with_enclosing_digest_separate():
    row = {"application_id": "app-a", "profile_id": "profile-a",
           "profile_generation": "process-g1", "capability_ids": ["application:run"],
           "provider_route_ids": [], "credential_reference_ids": []}
    catalog = ProtectedEnrollmentCatalog(
        {("service-a", "process-g1"): SimpleNamespace()}, digest="a" * 64,
        selected_application_runtimes=[row],
    )
    selected = catalog.selected_application_runtime_record("app-a")
    assert selected["capability_ids"] == ("application:run",)
    assert "service_generation_digest" not in selected
    assert catalog.digest == "a" * 64
    with pytest.raises(EnrollmentDenied, match="not enrolled"):
        catalog.selected_application_runtime_record("app-missing")
    with pytest.raises(EnrollmentDenied, match="ambiguous"):
        ProtectedEnrollmentCatalog(
            {("service-a", "process-g1"): SimpleNamespace()}, digest="a" * 64,
            selected_application_runtimes=[row, {**row, "profile_id": "profile-b"}],
        )


def _private_endpoint_row(**overrides):
    row = {
        "binding_id": "endpoint-selection-a", "profile_id": "profile-a",
        "namespace_id": "namespace-a", "principal_id": "principal-a",
        "service_enrollment_id": "service-a", "service_generation": "memory-gen-a",
        "process_profile_id": "server-profile-a", "process_profile_generation": "process-gen-a",
        "endpoint_target_id": "memory-openviking:profile-a", "connector_route_ids": ["memory-search-v1"],
        "recipient_id": "recipient-a", "credential_reference_id": "credential-a",
        "server_config_artifact_id": "server-config-a", "server_config_sha256": "a" * 64,
        "runtime_artifact_ids": ["server-runtime-a"], "network_binding_handle": "network-receipt-a",
    }
    row.update(overrides)
    return row


def _private_model_row(**overrides):
    row = {
        "binding_id": "model-selection-a", "endpoint_binding_id": "endpoint-selection-a",
        "served_model_id": "private-model-a", "source_model_id": "source-model-a",
        "source_revision": "revision-a", "license_artifact_id": "license-a",
        "license_sha256": "b" * 64, "model_artifact_id": "model-a",
        "model_artifact_sha256": "c" * 64, "model_tree_manifest_sha256": "d" * 64,
        "runtime_artifact_id": "model-runtime-a", "runtime_artifact_sha256": "e" * 64,
        "load_config_artifact_id": "load-config-a", "load_config_sha256": "f" * 64,
        "capability": "extraction-text", "dimensions": None,
    }
    row.update(overrides)
    return row


def test_private_memory_selection_dtos_are_exact_immutable_and_dimension_typed():
    from hermes_installer.protected_enrollment import (
        RootSelectedPrivateMemoryEndpointBinding, RootSelectedPrivateMemoryModelBinding,
    )
    endpoint = RootSelectedPrivateMemoryEndpointBinding.from_protected_record(
        _private_endpoint_row(), service_generation_digest="9" * 64,
    )
    assert endpoint.connector_route_ids == ("memory-search-v1",)
    assert endpoint.service_generation_digest == "9" * 64
    assert "service_generation_digest" not in _private_endpoint_row()
    model = RootSelectedPrivateMemoryModelBinding.from_protected_record(
        _private_model_row(), service_generation_digest="9" * 64,
    )
    assert model.dimensions is None and model.capability == "extraction-text"
    embedding = RootSelectedPrivateMemoryModelBinding.from_protected_record(
        _private_model_row(capability="embedding", dimensions=768), service_generation_digest="9" * 64,
    )
    assert embedding.dimensions == 768
    bad_rows = [
        _private_endpoint_row(service_generation_digest="9" * 64),
        _private_endpoint_row(connector_route_ids=["memory-search-v1", "memory-search-v1"]),
        _private_endpoint_row(server_config_sha256="not-a-digest"),
    ]
    for row in bad_rows:
        with pytest.raises(EnrollmentDenied):
            RootSelectedPrivateMemoryEndpointBinding.from_protected_record(
                row, service_generation_digest="9" * 64,
            )
    for override in ({"capability": "extraction-text", "dimensions": 768},
                     {"capability": "embedding", "dimensions": None},
                     {"capability": "embedding", "dimensions": 8193}):
        with pytest.raises(EnrollmentDenied):
            RootSelectedPrivateMemoryModelBinding.from_protected_record(
                _private_model_row(**override), service_generation_digest="9" * 64,
            )


def test_private_memory_catalog_getters_rejoin_exact_service_routes_and_endpoint(monkeypatch):
    profile = SimpleNamespace(
        enrollment_id="service-a", generation="memory-gen-a", profile_id="profile-a",
        principal_id="principal-a", namespace_identity="namespace-a",
    )
    process = SimpleNamespace(
        enrollment_id="server-enrollment-a", generation="process-gen-a",
        profile_id="server-profile-a", principal_id="principal-a",
        namespace_identity="namespace-a",
    )
    memory = SimpleNamespace(
        service_enrollment_id="service-a", service_generation="memory-gen-a",
        profile_id="profile-a", principal_id="principal-a", namespace_identity="namespace-a",
        target_id="memory-openviking:profile-a", auth_reference_id="credential-a",
        fixed_route_map={"memory-search-v1": object()},
    )
    monkeypatch.setattr(ProtectedEnrollmentCatalog, "resolve", lambda self, *_: profile)
    monkeypatch.setattr(ProtectedEnrollmentCatalog, "resolve_profile_generation", lambda self, *_: process)
    resolved_routes = []
    monkeypatch.setattr(
        ProtectedEnrollmentCatalog, "resolve_connector_route",
        lambda self, _enrollment, _generation, _target, route: resolved_routes.append(route) or object(),
    )
    catalog = ProtectedEnrollmentCatalog(
        {("service-a", "memory-gen-a"): profile}, digest="9" * 64,
        memory_enrollments={("service-a", "memory-gen-a"): memory},
        private_memory_endpoint_selections=[_private_endpoint_row()],
        private_memory_model_selections=[_private_model_row()],
    )
    endpoint = catalog.resolve_private_memory_endpoint_binding("endpoint-selection-a")
    selected_endpoint = catalog.resolve_private_memory_endpoint_for_service(
        "service-a", "memory-gen-a", "profile-a", "principal-a",
    )
    model = catalog.resolve_private_memory_model_binding("model-selection-a", "endpoint-selection-a")
    assert endpoint.service_generation_digest == catalog.digest
    assert selected_endpoint is endpoint
    assert model.endpoint_binding_id == endpoint.binding_id
    assert resolved_routes == ["memory-search-v1"] * 4
    with pytest.raises(EnrollmentDenied, match="another endpoint"):
        catalog.resolve_private_memory_model_binding("model-selection-a", "other-endpoint")
    with pytest.raises(EnrollmentDenied, match="absent or stale"):
        catalog.resolve_private_memory_model_binding("unknown-model")
    with pytest.raises(EnrollmentDenied, match="no unique selected endpoint"):
        catalog.resolve_private_memory_endpoint_for_service(
            "service-a", "memory-gen-a", "profile-a", "other-principal",
        )


def test_private_memory_catalog_denies_stale_process_join_and_unknown_model_endpoint(monkeypatch):
    profile = SimpleNamespace(
        enrollment_id="service-a", generation="memory-gen-a", profile_id="profile-a",
        principal_id="principal-a", namespace_identity="namespace-a",
    )
    process = SimpleNamespace(
        enrollment_id="server-enrollment-a", generation="process-gen-wrong",
        profile_id="server-profile-a", principal_id="principal-a",
        namespace_identity="namespace-a",
    )
    memory = SimpleNamespace(
        service_enrollment_id="service-a", service_generation="memory-gen-a",
        profile_id="profile-a", principal_id="principal-a", namespace_identity="namespace-a",
        target_id="memory-openviking:profile-a", auth_reference_id="credential-a",
        fixed_route_map={"memory-search-v1": object()},
    )
    monkeypatch.setattr(ProtectedEnrollmentCatalog, "resolve", lambda self, *_: profile)
    monkeypatch.setattr(ProtectedEnrollmentCatalog, "resolve_profile_generation", lambda self, *_: process)
    monkeypatch.setattr(ProtectedEnrollmentCatalog, "resolve_connector_route", lambda self, *_: object())
    with pytest.raises(EnrollmentDenied, match="stale or incomplete"):
        ProtectedEnrollmentCatalog(
            {("service-a", "memory-gen-a"): profile}, digest="9" * 64,
            memory_enrollments={("service-a", "memory-gen-a"): memory},
            private_memory_endpoint_selections=[_private_endpoint_row()],
        )

    process.generation = "process-gen-a"
    with pytest.raises(EnrollmentDenied, match="foreign key"):
        ProtectedEnrollmentCatalog(
            {("service-a", "memory-gen-a"): profile}, digest="9" * 64,
            memory_enrollments={("service-a", "memory-gen-a"): memory},
            private_memory_endpoint_selections=[_private_endpoint_row()],
            private_memory_model_selections=[_private_model_row(endpoint_binding_id="other-endpoint")],
        )


def test_fixed_build_record_rejects_unlisted_target_and_caller_recipe_fields():
    item = build_record("arbitrary-shell:start")
    with pytest.raises(EnrollmentDenied):
        FixedBuildProfile.from_protected_record(item)
    item = build_record()
    item["argv_recipe"] = ["/bin/sh", "-c", "{caller_command}"]
    with pytest.raises(EnrollmentDenied):
        FixedBuildProfile.from_protected_record(item)


def test_build_output_constraints_are_root_reviewed_and_contain_no_preknown_digest():
    profile = FixedBuildProfile.from_protected_record(build_record())
    output = profile.output_specs["runtime/bin/python3.9"]
    assert (output.kind, output.maximum_bytes, output.executable_role) == (
        "file", 67108864, "coral-cpython39")
    assert output.target_facts["soabi"] == "cpython-39-aarch64-linux-gnu"
    unreviewed = build_record()
    unreviewed["output_specs"][0]["sha256"] = "f" * 64
    with pytest.raises(EnrollmentDenied, match="output constraint fields"):
        FixedBuildProfile.from_protected_record(unreviewed)


def test_fixed_build_argv_accepts_only_tagged_literals_and_fixed_mount_paths():
    parsed = FixedBuildProfile.from_protected_record(build_record())
    assert parsed.argv_recipe[0] == {"build_path": {"mount_id": "builder", "relative_path": ""}}
    assert parsed.argv_recipe[1] == {"literal": "--profile"}

    invalid_recipes = [
        ["/opt/hermes/build-driver"],  # legacy strings cannot be active authority
        [{"literal": "builder"}],  # argv[0] must be the exact builder mount
        [{"build_path": {"mount_id": "etc", "relative_path": "passwd"}}],
        [{"build_path": {"mount_id": "builder", "relative_path": "../escape"}}],
        [{"build_path": {"mount_id": "builder", "relative_path": "/tmp/escape"}}],
        [{"build_path": {"mount_id": "builder", "relative_path": ""}, "literal": "extra"}],
    ]
    for recipe in invalid_recipes:
        item = build_record()
        item["argv_recipe"] = recipe
        with pytest.raises(EnrollmentDenied):
            FixedBuildProfile.from_protected_record(item)


def test_fixed_build_profile_binds_dedicated_service_enrollment():
    profile = FixedBuildProfile.from_protected_record(build_record())
    assert profile.build_service_enrollment_id == "build-service-a"
    assert profile.build_service_generation == "build-service-generation-a"
    unbound = build_record()
    del unbound["build_service_enrollment_id"]
    with pytest.raises(EnrollmentDenied):
        FixedBuildProfile.from_protected_record(unbound)


def test_build_catalog_joins_only_exact_selected_process_service_and_owner(monkeypatch):
    import hermes_installer.protected_enrollment as protected

    build = FixedBuildProfile.from_protected_record(build_record())
    build_catalog = ProtectedBuildCatalog({(build.target_id, build.generation): build})
    selected_service = SimpleNamespace(
        enrollment_id=build.build_service_enrollment_id,
        generation=build.build_service_generation,
        operation_targets={"process.start": build.target_id},
        service_uid=build.output_owner_uid, service_gid=1234, service_user="hermes-build",
    )
    monkeypatch.setattr(protected.pwd, "getpwnam",
                        lambda _name: SimpleNamespace(pw_uid=build.output_owner_uid, pw_gid=1234))
    monkeypatch.setattr(protected.grp, "getgrgid",
                        lambda _gid: SimpleNamespace(gr_mem=[]))
    monkeypatch.setattr(protected.pwd, "getpwall",
                        lambda: [SimpleNamespace(pw_name="hermes-build", pw_gid=1234)])

    class Services:
        def resolve(self, enrollment_id, generation):
            assert enrollment_id == build.build_service_enrollment_id
            assert generation == build.build_service_generation
            return selected_service

    resolved, service = build_catalog.resolve_service(build.target_id, build.generation, Services())
    assert resolved.target_id == build.target_id and service is selected_service

    selected_service.service_uid += 1
    with pytest.raises(EnrollmentDenied):
        build_catalog.resolve_service(build.target_id, build.generation, Services())


def test_usb_and_pci_selection_stay_opaque_and_generation_bound(monkeypatch):
    records = [{
        "device_id": "tpu-usb-main", "transport": "usb", "physical_identity": "1-2.3",
        "sysfs_path": "/sys/bus/usb/devices/1-2.3", "device_node": "/dev/bus/usb/001/004",
        "major": 189, "minor": 3, "inode": 99, "generation": "usb-g1",
        "vendor_id": "18d1", "product_id": "9302", "interface_identity": "1-2.3:1.0",
        "interface_sysfs_path": "/sys/bus/usb/devices/1-2.3:1.0", "driver": None,
    }]
    catalog = ProtectedDeviceCatalog.from_protected_records(records)
    selected = catalog._devices["tpu-usb-main"]
    monkeypatch.setattr(type(selected), "verify_current", lambda _self: None)
    resolved = catalog.resolve("tpu-usb-main", "usb-g1")
    assert resolved.device_allow == "char-189:3:rwm"
    assert len(resolved.selection_digest) == 64
    with pytest.raises(EnrollmentDenied):
        catalog.resolve("tpu-usb-main", "usb-g2")
    with pytest.raises(EnrollmentDenied):
        catalog.resolve("/dev/bus/usb/001/004", "usb-g1")
    with pytest.raises(EnrollmentDenied, match="exact sysfs interface"):
        ProtectedDeviceCatalog.from_protected_records([{**records[0], "interface_identity": "1-2.4:1.0"}])


def test_service_profile_joins_exact_independent_device_generation(monkeypatch):
    profile_record = {
        "enrollment_id": "coral-enrollment", "generation": "service-g7", "profile_id": "coral-worker",
        "principal_id": "coral-owner", "service_uid": 1001, "service_gid": 1001,
        "service_user": "hermes-owner", "device_enrollment_id": "coral-usb-device",
        "expected_device_generation": "device-g3", "executable": "/opt/hermes/bin/worker",
        "executable_sha256": "a" * 64, "runtime_artifact_ids": ["runtime-v1"],
        "package_runtime_records": {},
        "roots": {"home_id": "home", "work_id": "work", "data_id": "data",
                  "home": "/var/lib/hermes/home", "work": "/var/lib/hermes/work", "data": "/var/lib/hermes/data"},
        "authority_endpoint_id": "coral-socket", "namespace_identity": "coral-ns",
        "socket_policy_id": "coral-sockets", "target_route_ids": [],
        "operation_targets": {"process.start": "coral-start"},
        "operation_recipes": {"coral-inference": launch_recipe("data")},
        "argv_recipe": ["/opt/hermes/bin/worker"], "environment": {},
        "max_lifetime_seconds": 600, "memory_max_bytes": 1000000,
        "cpu_quota_percent": 100, "io_weight": 100,
    }
    profile = _parse_profile(profile_record)
    device_record = {
        "device_id": "coral-usb-device", "transport": "usb", "physical_identity": "1-2.3",
        "sysfs_path": "/sys/bus/usb/devices/1-2.3", "device_node": "/dev/bus/usb/001/004",
        "major": 189, "minor": 3, "inode": 99, "generation": "device-g3",
        "vendor_id": "18d1", "product_id": "9302", "interface_identity": "1-2.3:1.0",
        "interface_sysfs_path": "/sys/bus/usb/devices/1-2.3:1.0", "driver": None,
    }
    devices = ProtectedDeviceCatalog.from_protected_records([device_record])
    monkeypatch.setattr(type(devices._devices["coral-usb-device"]), "verify_current", lambda _self: None)
    catalog = ProtectedEnrollmentCatalog({("coral-enrollment", "service-g7"): profile}, digest="0" * 64)
    catalog.resolve = lambda enrollment_id, generation: profile if (
        enrollment_id, generation) == ("coral-enrollment", "service-g7") else (
            _ for _ in ()).throw(EnrollmentDenied("stale service generation"))
    selected = catalog.resolve_device("coral-enrollment", "service-g7", devices)
    assert (selected.generation, selected.device_allow) == ("device-g3", "char-189:3:rwm")
    with pytest.raises(EnrollmentDenied):
        catalog.resolve_device("coral-enrollment", "stale-service-generation", devices)


def test_catalog_rejects_duplicate_physical_devices():
    row = {
        "device_id": "tpu-a", "transport": "pci", "physical_identity": "0000:01:00.0",
        "sysfs_path": "/sys/bus/pci/devices/0000:01:00.0", "device_node": "/dev/apex_0",
        "major": 120, "minor": 0, "inode": 10, "generation": "pci-g1",
        "vendor_id": "1ac1", "product_id": "089a", "interface_identity": None,
        "interface_sysfs_path": None, "driver": "apex",
    }
    twin = {**row, "device_id": "tpu-b"}
    with pytest.raises(EnrollmentDenied, match="multiple active"):
        ProtectedDeviceCatalog.from_protected_records([row, twin])


def test_profile_rejects_caller_selected_roots_and_malformed_recipe(monkeypatch):
    # Profile parsing accepts only the complete root-owned schema; it does not
    # accept filesystem authorities through a call payload.
    item = {
        "enrollment_id": "install-1", "generation": "gen-1", "profile_id": "hermes-main",
            "principal_id": "owner", "service_uid": 1001, "service_gid": 1001, "service_user": "hermes-owner",
            "device_enrollment_id": None, "expected_device_generation": None,
            "executable": "/opt/hermes/bin/hermes", "executable_sha256": "a" * 64,
            "runtime_artifact_ids": ["hermes-runtime-v1"], "package_runtime_records": {},
        "roots": {"home_id": "home", "work_id": "work", "data_id": "data",
                  "home": "/var/lib/hermes/home", "work": "/var/lib/hermes/work", "data": "/var/lib/hermes/data"},
        "authority_endpoint_id": "owner-socket", "namespace_identity": "hermes-ns", "target_route_ids": ["http-api"],
        "socket_policy_id": "hermes-sockets", "operation_targets": {"process.start": "start-target"},
        "operation_recipes": {"hermes-server-start": launch_recipe("data")},
        "argv_recipe": ["/opt/hermes/bin/hermes", "serve"], "environment": {"HOME": "/var/lib/hermes/home"},
        "max_lifetime_seconds": 600, "memory_max_bytes": 1000000,
        "cpu_quota_percent": 100, "io_weight": 100,
    }
    parsed = _parse_profile(item)
    assert parsed.roots.home != parsed.roots.work != parsed.roots.data
    catalog = ProtectedEnrollmentCatalog({("install-1", "gen-1"): parsed}, digest="0" * 64)
    monkeypatch.setattr(catalog, "resolve", lambda *_args: parsed)
    binding = catalog.resolve_operation("install-1", "gen-1", "process.start")
    assert (binding.target_id, binding.service_uid, binding.service_gid) == ("start-target", 1001, 1001)
    with pytest.raises(EnrollmentDenied):
        catalog.resolve_operation("install-1", "gen-1", "arbitrary-shell")
    with pytest.raises(EnrollmentDenied):
        _parse_profile({**item, "roots": {**item["roots"], "data": "/tmp/caller-root"}, "argv": ["bad"]})


def test_native_package_record_is_typed_and_resolved_only_for_current_service_generation(monkeypatch):
    item = {
        "enrollment_id": "install-1", "generation": "gen-1", "profile_id": "hermes-main",
        "principal_id": "owner", "service_uid": 1001, "service_gid": 1001, "service_user": "hermes-owner",
        "device_enrollment_id": None, "expected_device_generation": None,
        "executable": "/opt/hermes/bin/hermes", "executable_sha256": "a" * 64,
        "runtime_artifact_ids": ["hermes-runtime-v1"], "package_runtime_records": {},
        "roots": {"home_id": "home", "work_id": "work", "data_id": "data",
                  "home": "/var/lib/hermes/home", "work": "/var/lib/hermes/work", "data": "/var/lib/hermes/data"},
        "authority_endpoint_id": "owner-socket", "namespace_identity": "hermes-ns", "target_route_ids": ["http-api"],
        "socket_policy_id": "hermes-sockets", "operation_targets": {"process.start": "start-target"},
        "operation_recipes": {"hermes-server-start": launch_recipe("data")},
        "argv_recipe": ["/opt/hermes/bin/hermes", "serve"], "environment": {"HOME": "/var/lib/hermes/home"},
        "max_lifetime_seconds": 600, "memory_max_bytes": 1000000,
        "cpu_quota_percent": 100, "io_weight": 100,
    }
    profile = _parse_profile(item)
    record = {
        "package_id": "desktop-native", "profile_id": profile.profile_id,
        "generation": "native-gen-1", "profile_generation": profile.generation,
        "source_revision": "rev-1",
        "source_tree_sha256": "b" * 64,
        "compiled_closure_artifact_id": "compiled-closure", "compiled_closure_sha256": "c" * 64,
        "entrypoint_artifact_id": "plugin-entrypoint", "entrypoint_sha256": "d" * 64,
        "resolver_artifact_id": "plugin-resolver", "resolver_sha256": "e" * 64,
        "service_package_root_id": "desktop-package-root", "service_mount_id": "desktop-package-mount",
        "adapter_records": [],
        "action_records": [{
            "action_binding_id": "adapter-one:action:read", "adapter_id": "adapter-one",
            "action_id": "read", "manifest_sha256": "f" * 64,
            "adapter_artifact_id": "adapter-one-artifact", "adapter_sha256": "0" * 64,
            "argument_schema_id": "read-input-v1", "result_schema_id": "read-result-v1",
            "effect_enrollment_id": "effect-enrollment", "operation": "plugin.adapter-one.read",
            "capability": "plugin:adapter-one", "target_id": "example-target",
            "recipient": "example-recipient", "generation": "native-gen-1",
            "observer_enrollment_ids": [],
        }],
        "registration_records": [], "workflow_records": [], "process_role_records": [],
    }
    catalog = ProtectedEnrollmentCatalog({("install-1", "gen-1"): profile}, digest="0" * 64,
                                         native_packages=[record])
    monkeypatch.setattr(catalog, "resolve", lambda enrollment_id, generation: profile
                        if (enrollment_id, generation) == ("install-1", "gen-1")
                        else (_ for _ in ()).throw(EnrollmentDenied("stale")))
    resolved = catalog.resolve_native_package("desktop-native", "native-gen-1")
    assert resolved.service_mount_id == "desktop-package-mount"
    assert resolved.action_records["adapter-one:action:read"].operation == "plugin.adapter-one.read"
    assert resolved.profile_generation == profile.generation
    with pytest.raises(EnrollmentDenied):
        catalog.resolve_native_package("desktop-native", "stale-generation")


def test_native_observer_reference_joins_exact_active_issuer_role():
    from hermes_installer.authority.enrollment import SourceIssuerRecord

    item = {
        "enrollment_id": "install-1", "generation": "gen-1", "profile_id": "hermes-main",
        "principal_id": "owner", "service_uid": 1001, "service_gid": 1001, "service_user": "hermes-owner",
        "device_enrollment_id": None, "expected_device_generation": None,
        "executable": "/opt/hermes/bin/hermes", "executable_sha256": "a" * 64,
        "runtime_artifact_ids": ["hermes-runtime-v1"], "package_runtime_records": {},
        "roots": {"home_id": "home", "work_id": "work", "data_id": "data",
                  "home": "/var/lib/hermes/home", "work": "/var/lib/hermes/work", "data": "/var/lib/hermes/data"},
        "authority_endpoint_id": "owner-socket", "namespace_identity": "hermes-ns", "target_route_ids": ["http-api"],
        "socket_policy_id": "hermes-sockets", "operation_targets": {"process.start": "start-target"},
        "operation_recipes": {"hermes-server-start": launch_recipe("data")},
        "argv_recipe": ["/opt/hermes/bin/hermes", "serve"], "environment": {"HOME": "/var/lib/hermes/home"},
        "max_lifetime_seconds": 600, "memory_max_bytes": 1000000,
        "cpu_quota_percent": 100, "io_weight": 100,
    }
    profile = _parse_profile(item)
    package = {
        "package_id": "desktop-native", "profile_id": profile.profile_id,
        "generation": "native-gen-1", "profile_generation": profile.generation,
        "source_revision": "rev-1",
        "source_tree_sha256": "b" * 64,
        "compiled_closure_artifact_id": "compiled-closure", "compiled_closure_sha256": "c" * 64,
        "entrypoint_artifact_id": "plugin-entrypoint", "entrypoint_sha256": "d" * 64,
        "resolver_artifact_id": "plugin-resolver", "resolver_sha256": "e" * 64,
        "service_package_root_id": "desktop-package-root", "service_mount_id": "desktop-package-mount",
        "adapter_records": [],
        "action_records": [{
            "action_binding_id": "adapter-one:action:read", "adapter_id": "adapter-one",
            "action_id": "read", "manifest_sha256": "f" * 64,
            "adapter_artifact_id": "adapter-one-artifact", "adapter_sha256": "0" * 64,
            "argument_schema_id": "read-input-v1", "result_schema_id": "read-result-v1",
            "effect_enrollment_id": "effect-enrollment", "operation": "plugin.adapter-one.read",
            "capability": "plugin:adapter-one", "target_id": "example-target",
            "recipient": "example-recipient", "generation": "native-gen-1",
            "observer_enrollment_ids": ["observer-one"],
        }],
        "registration_records": [], "workflow_records": [], "process_role_records": [{
            "role_id": "result-role", "package_id": "desktop-native",
            "native_package_generation": "native-gen-1", "profile_id": profile.profile_id,
            "profile_generation": profile.generation, "role_artifact_id": "process-result-role",
            "role_sha256": "1" * 64, "role_source_receipt_handle": "role-source-receipt",
            "module_name": "hermes_installer.adapters.result_role",
            "closure_member_path": "hermes_installer/adapters/result_role.py",
            "role_source_revision": "rev-1", "role_source_tree_sha256": "2" * 64,
            "observer_enrollment_ids": ["observer-one"], "registration_ids": [],
            "action_binding_ids": ["adapter-one:action:read"], "workflow_ids": [],
        }],
    }
    issuer = SourceIssuerRecord(
        "tool-result", profile.profile_id, "process-result-role", "1" * 64,
        "read-result-v1", (), profile.generation, "observer-one", ("read",),
    )
    catalog = ProtectedEnrollmentCatalog({("install-1", "gen-1"): profile}, digest="0" * 64,
                                         native_packages=[package], source_issuers=[issuer])
    catalog.resolve = lambda *_args: profile
    role = catalog.resolve_selected_native_process_role("desktop-native", "native-gen-1", "result-role")
    assert role.role_artifact_id == "process-result-role"
    join = catalog.source_observer_joins["observer-one"]
    assert join.process_role == role
    assert join.actions["adapter-one:action:read"].adapter_artifact_id == "adapter-one-artifact"

    for mutate, message in (
        (lambda row: row.__setitem__("closure_member_path", "../outside.py"), "normalized and relative"),
        (lambda row: row.__setitem__("profile_generation", "stale-process-generation"), "another package or profile generation"),
        (lambda row: row.__setitem__("role_sha256", "not-a-digest"), "digest"),
    ):
        invalid = copy.deepcopy(package)
        mutate(invalid["process_role_records"][0])
        with pytest.raises(EnrollmentDenied, match=message):
            NativePackageBinding.from_protected_record(invalid)

    with pytest.raises(EnrollmentDenied, match="exact active source issuer"):
        ProtectedEnrollmentCatalog(
            {("install-1", "gen-1"): profile}, digest="0" * 64,
            native_packages=[package], source_issuers=[
                SourceIssuerRecord("tool-result", profile.profile_id, "different-role", "0" * 64,
                                   "read-result-v1", (), profile.generation, "observer-one", ("read",))
            ],
        )
    with pytest.raises(EnrollmentDenied, match="exact active source issuer"):
        ProtectedEnrollmentCatalog(
            {("install-1", "gen-1"): profile}, digest="0" * 64,
            native_packages=[package], source_issuers=[
                SourceIssuerRecord("tool-result", profile.profile_id, "different-role", "0" * 64,
                                   "read-result-v1", (), "stale-process-gen", "observer-one",
                                   ("registered-tool-result",))
            ],
        )


def test_v113_native_package_keeps_effect_actions_separate_from_registered_tools():
    from hermes_installer.protected_enrollment import NativePackageBinding

    action_base = {
        "adapter_id": "adapter", "manifest_sha256": "1" * 64,
        "adapter_artifact_id": "adapter-code", "adapter_sha256": "2" * 64,
        "argument_schema_id": "action-args-v1", "result_schema_id": "action-result-v1",
        "effect_enrollment_id": "effect-a", "operation": "plugin.adapter.read",
        "capability": "plugin:adapter", "target_id": "target-a", "recipient": None,
        "generation": "package-g2", "observer_enrollment_ids": [],
    }
    actions = [
        {**action_base, "action_id": action_id,
         "action_binding_id": f"adapter:action:{action_id}"}
        for action_id in ("read", "write")
    ]
    registration = {
        "registration_id": "adapter:tool:query", "native_tool_name": "query",
        "native_server_name": "hermes-installer", "toolset": "filesystem", "family": "files",
        "adapter_id": "adapter", "argument_schema_id": "tool-args-v1",
        "result_schema_id": "tool-result-v1", "native_schema_sha256": "3" * 64,
        "registration_source_artifact_id": "registration-source",
        "registration_source_sha256": "4" * 64,
        "registration_source_receipt_handle": "receipt-source",
        "handler_kind": "effect-action", "handler_id": "read-handler",
        "selector_fields": [],
        "action_bindings": [{
            "selector_values": {}, "action_binding_id": "adapter:action:read",
            "argument_projection": [{"name": "query", "source_field": "query"}],
            "workflow_id": None,
        }],
        "observer_enrollment_ids": [], "generation": "package-g2",
    }
    package = NativePackageBinding.from_protected_record({
        "package_id": "package-a", "profile_id": "profile-a", "generation": "package-g2",
        "profile_generation": "process-g5", "source_revision": "rev-a",
        "source_tree_sha256": "5" * 64, "compiled_closure_artifact_id": "closure-a",
        "compiled_closure_sha256": "6" * 64, "entrypoint_artifact_id": "entry-a",
        "entrypoint_sha256": "7" * 64, "resolver_artifact_id": "resolver-a",
        "resolver_sha256": "8" * 64, "service_package_root_id": "root-a",
        "service_mount_id": "mount-a", "adapter_records": [],
        "action_records": actions, "registration_records": [registration],
        "workflow_records": [], "process_role_records": [],
    })
    assert set(package.action_records) == {"adapter:action:read", "adapter:action:write"}
    assert package.registration_records["adapter:tool:query"].action_bindings[0].action_binding_id == "adapter:action:read"
    assert package.generation != package.profile_generation
    with pytest.raises(TypeError):
        package.action_records["extra"] = package.action_records["adapter:action:read"]

    bad = dict(registration)
    bad["action_bindings"] = [{**registration["action_bindings"][0],
                               "action_binding_id": "adapter:action:missing"}]
    malformed = {
        "package_id": "package-a", "profile_id": "profile-a", "generation": "package-g2",
        "profile_generation": "process-g5", "source_revision": "rev-a",
        "source_tree_sha256": "5" * 64, "compiled_closure_artifact_id": "closure-a",
        "compiled_closure_sha256": "6" * 64, "entrypoint_artifact_id": "entry-a",
        "entrypoint_sha256": "7" * 64, "resolver_artifact_id": "resolver-a",
        "resolver_sha256": "8" * 64, "service_package_root_id": "root-a",
        "service_mount_id": "mount-a", "adapter_records": [],
        "action_records": actions, "registration_records": [bad], "workflow_records": [],
        "process_role_records": [],
    }
    with pytest.raises(EnrollmentDenied, match="action binding is absent"):
        NativePackageBinding.from_protected_record(malformed)


def test_v113_native_workflow_refs_are_ordered_and_owned_by_the_registration():
    from hermes_installer.protected_enrollment import NativePackageBinding

    action = {
        "action_binding_id": "adapter:action:step", "adapter_id": "adapter", "action_id": "step",
        "manifest_sha256": "1" * 64, "adapter_artifact_id": "adapter-code", "adapter_sha256": "2" * 64,
        "argument_schema_id": "step-args", "result_schema_id": "step-result",
        "effect_enrollment_id": "effect-step", "operation": "plugin.adapter.step",
        "capability": "plugin:adapter", "target_id": "target", "recipient": None,
        "generation": "pkg-1", "observer_enrollment_ids": [],
    }
    registration = {
        "registration_id": "adapter:tool:voice", "native_tool_name": "voice",
        "native_server_name": "hermes-installer", "toolset": "voice", "family": "voice",
        "adapter_id": "adapter", "argument_schema_id": "voice-args", "result_schema_id": "voice-result",
        "native_schema_sha256": "3" * 64, "registration_source_artifact_id": "reg-src",
        "registration_source_sha256": "4" * 64, "registration_source_receipt_handle": "reg-receipt",
        "handler_kind": "finite-workflow", "handler_id": "voice-workflow",
        "selector_fields": [], "action_bindings": [{
            "selector_values": {}, "action_binding_id": None, "argument_projection": [],
            "workflow_id": "workflow-1",
        }], "observer_enrollment_ids": [], "generation": "pkg-1",
    }
    workflow = {
        "id": "workflow-1", "registration_id": registration["registration_id"],
        "external_argument_schema_id": "voice-args", "external_result_schema_id": "voice-result",
        "workflow_artifact_id": "workflow-code", "workflow_sha256": "5" * 64,
        "workflow_source_receipt_handle": "workflow-receipt",
        "step_action_binding_ids": ["adapter:action:step"], "generation": "pkg-1",
    }
    row = {
        "package_id": "package", "profile_id": "profile", "generation": "pkg-1",
        "profile_generation": "process-4", "source_revision": "rev",
        "source_tree_sha256": "6" * 64, "compiled_closure_artifact_id": "closure",
        "compiled_closure_sha256": "7" * 64, "entrypoint_artifact_id": "entry",
        "entrypoint_sha256": "8" * 64, "resolver_artifact_id": "resolver",
        "resolver_sha256": "9" * 64, "service_package_root_id": "root",
        "service_mount_id": "mount", "adapter_records": [], "action_records": [action],
        "registration_records": [registration], "workflow_records": [workflow], "process_role_records": [],
    }
    parsed = NativePackageBinding.from_protected_record(row)
    assert parsed.workflow_records["workflow-1"].step_action_binding_ids == ("adapter:action:step",)

    from types import SimpleNamespace
    profile = SimpleNamespace(enrollment_id="install", profile_id="profile", generation="process-4")
    schema_rows = []
    for adapter_id, action_id, schema_id, kind in (
        ("adapter", "step", "step-args", "arguments"),
        ("adapter", "step", "step-result", "result"),
        ("adapter", "adapter:tool:voice", "voice-args", "arguments"),
        ("adapter", "adapter:tool:voice", "voice-result", "result"),
    ):
        schema_rows.append({
            "id": schema_id, "artifact_id": f"artifact-{schema_id}", "sha256": "a" * 64,
            "schema_kind": kind, "native_package_id": "package", "native_package_generation": "pkg-1",
            "adapter_id": adapter_id, "action_id": action_id, "source_receipt_handle": "receipt",
            "size_bytes": 10, "derivation_receipt_handle": None,
        })
    catalog = ProtectedEnrollmentCatalog(
        {("install", "process-4"): profile}, digest="d" * 64,
        native_packages=[row], native_schema_artifacts=schema_rows,
    )
    catalog.resolve = lambda *_args: profile
    assert catalog.resolve_native_registration_schema_artifact(
        "package", "pkg-1", "adapter:tool:voice", "arguments", profile_id="profile",
        process_generation="process-4", service_generation_digest="d" * 64,
    )["id"] == "voice-args"
    with pytest.raises(EnrollmentDenied, match="stale service snapshot"):
        catalog.resolve_native_registration_schema_artifact(
            "package", "pkg-1", "adapter:tool:voice", "arguments", profile_id="profile",
            process_generation="process-4", service_generation_digest="e" * 64,
        )
    malformed_schema_rows = [record for record in schema_rows if record["id"] != "voice-result"]
    with pytest.raises(EnrollmentDenied, match="registration schema join"):
        ProtectedEnrollmentCatalog(
            {("install", "process-4"): profile}, digest="d" * 64,
            native_packages=[row], native_schema_artifacts=malformed_schema_rows,
        )

    wrong_owner = {**workflow, "registration_id": "other:tool:voice"}
    with pytest.raises(EnrollmentDenied, match="workflow belongs to another registration"):
        NativePackageBinding.from_protected_record({**row, "workflow_records": [wrong_owner]})

    wrong_adapter = {**action, "adapter_id": "other", "action_id": "step",
                     "action_binding_id": "other:action:step", "operation": "plugin.other.step",
                     "capability": "plugin:other"}
    foreign_workflow = {**workflow, "step_action_binding_ids": ["other:action:step"]}
    with pytest.raises(EnrollmentDenied, match="workflow action belongs to another adapter"):
        NativePackageBinding.from_protected_record({**row, "action_records": [action, wrong_adapter],
                                                     "workflow_records": [foreign_workflow]})


def test_public_web_scope_parser_binds_canonical_payload_and_rejects_unsafe_targets():
    raw = {
        "enrollment_id": "web-scope-a", "target_id": "docs-a", "generation": "process-g1",
        "principal_id": "principal-a", "profile_id": "profile-a", "recipient": "recipient-a",
        "targets": [{"hostname": "docs.example.org", "path_prefixes": ["/api", "/docs"],
                     "query_keys": ["lang", "q"]}],
        "request_bytes_limit": 8192, "response_bytes_limit": 65536, "deadline_seconds": 10,
        "target_selection_handle": "selection-a", "configuration_observation_handle": "observation-a",
        "configuration_sha256": "a" * 64, "target_contract_artifact_id": "contract-a",
        "target_contract_sha256": "b" * 64, "target_contract_source_receipt_handle": "receipt-a",
    }
    parsed = RootSelectedPublicWebScope.from_protected_record(
        raw, service_generation_digest="c" * 64,
    )
    payload = {key: raw[key] for key in (
        "enrollment_id", "target_id", "generation", "principal_id", "profile_id", "recipient",
        "targets", "request_bytes_limit", "response_bytes_limit", "deadline_seconds",
    )}
    assert parsed.enrolled_scope.target == "plugin:web:docs-a:process-g1"
    assert parsed.enrolled_scope.targets[0].hostname == "docs.example.org"
    assert parsed.scope_payload_sha256 == hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    assert parsed.service_generation_digest == "c" * 64

    for bad in (
        {**raw, "extra": True},
        {**raw, "targets": [{**raw["targets"][0], "hostname": "127.0.0.1"}]},
        {**raw, "targets": [{**raw["targets"][0], "hostname": "docs.example.org."}]},
        {**raw, "targets": [{**raw["targets"][0], "path_prefixes": ["/docs/../private"]}]},
        {**raw, "targets": [{**raw["targets"][0], "path_prefixes": ["/docs/%2e%2e/private"]}]},
        {**raw, "targets": [{**raw["targets"][0], "path_prefixes": ["/docs", "/api"]}]},
        {**raw, "targets": [{**raw["targets"][0], "query_keys": ["access_token"]}]},
        {**raw, "deadline_seconds": True},
        {**raw, "response_bytes_limit": 2_097_153},
        {**raw, "configuration_sha256": "A" * 64},
    ):
        with pytest.raises(EnrollmentDenied):
            RootSelectedPublicWebScope.from_protected_record(
                bad, service_generation_digest="c" * 64,
            )


def test_public_web_scope_catalog_joins_exact_action_issuer_and_process_epoch(monkeypatch):
    from hermes_installer.authority.enrollment import SourceIssuerRecord

    profile = SimpleNamespace(profile_id="profile-a", generation="process-g1",
                              principal_id="principal-a", enrollment_id="service-a")
    action = {
        "action_binding_id": "web:action:read", "adapter_id": "web",
        "action_id": "read", "manifest_sha256": "1" * 64,
        "adapter_artifact_id": "adapter-code", "adapter_sha256": "2" * 64,
        "argument_schema_id": "web-args", "result_schema_id": "web-result",
        "effect_enrollment_id": "web-scope-a", "operation": "plugin.web.read",
        "capability": "plugin:web", "target_id": "plugin:web:docs-a:process-g1",
        "recipient": "recipient-a", "generation": "package-g1", "observer_enrollment_ids": [],
    }
    package = {
        "package_id": "package-a", "profile_id": "profile-a", "generation": "package-g1",
        "profile_generation": "process-g1", "source_revision": "rev-a",
        "source_tree_sha256": "3" * 64, "compiled_closure_artifact_id": "closure-a",
        "compiled_closure_sha256": "4" * 64, "entrypoint_artifact_id": "entry-a",
        "entrypoint_sha256": "5" * 64, "resolver_artifact_id": "resolver-a",
        "resolver_sha256": "6" * 64, "service_package_root_id": "root-a",
        "service_mount_id": "mount-a", "adapter_records": [], "action_records": [action],
        "registration_records": [], "workflow_records": [], "process_role_records": [],
    }
    issuer = SourceIssuerRecord(
        "native-input", "profile-a", "role-a", "7" * 64, "capture-v1", (),
        "process-g1", "observer-a", ("authenticated-input",), (), ("web-scope-a",),
    )
    raw_scope = {
        "enrollment_id": "web-scope-a", "target_id": "docs-a", "generation": "process-g1",
        "principal_id": "principal-a", "profile_id": "profile-a", "recipient": "recipient-a",
        "targets": [{"hostname": "docs.example.org", "path_prefixes": ["/docs"], "query_keys": ["q"]}],
        "request_bytes_limit": 8192, "response_bytes_limit": 65536, "deadline_seconds": 10,
        "target_selection_handle": "selection-a", "configuration_observation_handle": "observation-a",
        "configuration_sha256": "8" * 64, "target_contract_artifact_id": "contract-a",
        "target_contract_sha256": "9" * 64, "target_contract_source_receipt_handle": "receipt-a",
    }
    monkeypatch.setattr(ProtectedEnrollmentCatalog, "resolve", lambda self, *_args: profile)
    catalog = ProtectedEnrollmentCatalog(
        {("service-a", "process-g1"): profile}, digest="c" * 64,
        native_packages=[package], source_issuers=[issuer], public_web_scopes=[raw_scope],
    )
    selected = catalog.resolve_current_public_web_scopes(
        ["web-scope-a"], principal_id="principal-a", profile_id="profile-a",
        profile_generation="process-g1", service_generation_digest="c" * 64,
    )
    assert len(selected) == 1
    assert selected[0].target_selection_handle == "selection-a"
    assert catalog.resolve_current_public_web_scopes(
        [], principal_id="principal-a", profile_id="profile-a",
        profile_generation="process-g1", service_generation_digest="c" * 64,
    ) == ()
    with pytest.raises(EnrollmentDenied, match="principal/profile generation"):
        catalog.resolve_current_public_web_scopes(
            ["web-scope-a"], principal_id="other", profile_id="profile-a",
            profile_generation="process-g1", service_generation_digest="c" * 64,
        )
    with pytest.raises(EnrollmentDenied, match="stale generation"):
        catalog.resolve_current_public_web_scopes(
            ["web-scope-a"], principal_id="principal-a", profile_id="profile-a",
            profile_generation="process-g1", service_generation_digest="d" * 64,
        )
    with pytest.raises(EnrollmentDenied, match="source issuer"):
        ProtectedEnrollmentCatalog(
            {("service-a", "process-g1"): profile}, digest="c" * 64,
            native_packages=[package], source_issuers=[
                SourceIssuerRecord("native-input", "profile-a", "role-a", "7" * 64,
                                   "capture-v1", (), "other-generation", "observer-a",
                                   ("authenticated-input",), (), ("web-scope-a",)),
            ], public_web_scopes=[raw_scope],
        )
    with pytest.raises(EnrollmentDenied, match="sorted by enrollment ID"):
        ProtectedEnrollmentCatalog(
            {("service-a", "process-g1"): profile}, digest="c" * 64,
            native_packages=[package], source_issuers=[issuer],
            public_web_scopes=[raw_scope, {**raw_scope, "generation": "process-g2"}],
        )


def test_memory_connector_route_binds_variant_port_and_exact_route():
    item = {
        "enrollment_id": "memory-service", "generation": "service-g1", "profile_id": "memory-profile",
        "principal_id": "memory-owner", "service_uid": 1001, "service_gid": 1001,
        "device_enrollment_id": None, "expected_device_generation": None,
        "service_user": "hermes-owner", "executable": "/opt/hermes/bin/hermes",
        "executable_sha256": "a" * 64, "runtime_artifact_ids": ["runtime-v1"],
        "package_runtime_records": {},
        "roots": {"home_id": "home", "work_id": "work", "data_id": "store-root",
                  "home": "/var/lib/hermes/home", "work": "/var/lib/hermes/work", "data": "/var/lib/hermes/data"},
        "authority_endpoint_id": "owner-socket", "namespace_identity": "memory-ns",
        "socket_policy_id": "socket-policy", "target_route_ids": [], "operation_targets": {},
        "operation_recipes": {"hermes-server-start": launch_recipe("store-root")},
        "argv_recipe": ["/opt/hermes/bin/hermes", "serve"], "environment": {},
        "max_lifetime_seconds": 600, "memory_max_bytes": 1000000,
        "cpu_quota_percent": 100, "io_weight": 100,
    }
    profile = _parse_profile(item)
    memory = SimpleNamespace(
        profile_id=profile.profile_id, principal_id=profile.principal_id,
        provider="claude-mem", namespace_identity=profile.namespace_identity,
        data_root_id=profile.roots.data_id, literal_loopback_port=19331,
        backend_variant="server-v1-postgres",
        fixed_route_map={"claude-postgres-search": SimpleNamespace(
            backend_variant="server-v1-postgres",
            steps=(SimpleNamespace(
                step_id="search", method="POST", path_template="/v1/search",
                body_recipe_id="claude-search-request", response_schema_id="claude-search-result",
                capture_fields=(), next_step_id=None,
            ),),
            request_schema_id="claude-search-input", result_schema_id="claude-search-output",
            scope_bindings={"project": "root-project"}, credential_reference_id="memory-auth",
            maximum_seconds=10, maximum_bytes=100000,
        )},
    )
    catalog = ProtectedEnrollmentCatalog(
        {(profile.enrollment_id, profile.generation): profile}, digest="0" * 64,
        memory_enrollments={(profile.enrollment_id, profile.generation): memory},
    )
    catalog.resolve = lambda *_args: profile
    route = catalog.resolve_connector_route(
        profile.enrollment_id, profile.generation,
        "memory-claude-mem:memory-profile", "claude-postgres-search",
    )
    assert (route.backend_variant, route.literal_loopback_port) == ("server-v1-postgres", 19331)
    assert route.route_record["steps"][0]["path_template"] == "/v1/search"
    assert route.route_record["request_schema_id"] == "claude-search-input"
    with pytest.raises(EnrollmentDenied):
        catalog.resolve_connector_route(
            profile.enrollment_id, profile.generation,
            "memory-claude-mem:memory-profile", "claude-sqlite-search",
        )


def test_operation_parameter_schema_enforces_closed_types_and_finite_argv_values():
    schema = OperationParameterSchema.from_protected_record({
        "id": "build-options-v1",
        "fields": [
            {"name": "mode", "type": "string", "required": True,
             "enum": ["release", "debug"], "max_length": 16, "minimum": None, "maximum": None},
            {"name": "workers", "type": "integer", "required": True,
             "enum": None, "max_length": None, "minimum": 1, "maximum": 8},
            {"name": "clean", "type": "boolean", "required": True,
             "enum": None, "max_length": None, "minimum": None, "maximum": None},
        ],
    })
    assert dict(schema.validate({"mode": "release", "workers": 4, "clean": False})) == {
        "mode": "release", "workers": "4", "clean": "false",
    }
    for invalid in (
        {"mode": "release", "workers": True, "clean": False},
        {"mode": "release", "workers": 9, "clean": False},
        {"mode": "../../tmp", "workers": 4, "clean": False},
        {"mode": "release", "workers": 4, "clean": False, "extra": "x"},
    ):
        with pytest.raises(EnrollmentDenied):
            schema.validate(invalid)


def test_selection_only_launch_resolves_fixed_recipe_and_rejects_optional_argv_field(tmp_path: Path):
    roots = [tmp_path / name for name in ("home", "work", "data")]
    for root in roots:
        root.mkdir(mode=0o700)
    recipe = launch_recipe("data-root")
    recipe["argv_recipe"] = [{"literal": "serve"}, {"parameter": "profile"}]
    recipe["parameter_schema_id"] = "serve-parameters-v1"
    record = {
        "enrollment_id": "service-a", "generation": "gen-a", "profile_id": "profile-a",
        "principal_id": "principal-a", "service_uid": 1001, "service_gid": 1001,
        "service_user": "hermes-owner", "device_enrollment_id": None,
        "expected_device_generation": None, "executable": "/opt/hermes/bin/hermes",
        "executable_sha256": "a" * 64, "runtime_artifact_ids": ["runtime-v1"],
        "package_runtime_records": {},
        "roots": {"home_id": "home-root", "work_id": "work-root", "data_id": "data-root",
                  "home": str(roots[0]), "work": str(roots[1]), "data": str(roots[2])},
        "authority_endpoint_id": "socket-a", "namespace_identity": "ns-a",
        "socket_policy_id": "sockets-a", "target_route_ids": [],
        "operation_targets": {"process.start": "fixed-start-target"},
        "operation_recipes": {"hermes-serve-v1": recipe}, "argv_recipe": ["unused"],
        "environment": {}, "max_lifetime_seconds": 600, "memory_max_bytes": 1000000,
        "cpu_quota_percent": 100, "io_weight": 100,
    }
    profile = _parse_profile(record)
    schema_record = {"id": "serve-parameters-v1", "fields": [{
        "name": "profile", "type": "string", "required": True, "enum": ["production"],
        "max_length": 32, "minimum": None, "maximum": None,
    }]}
    catalog = ProtectedEnrollmentCatalog(
        {("service-a", "gen-a"): profile}, digest="a" * 64,
        parameter_schemas=[schema_record],
    )
    catalog.resolve = lambda *_args: profile
    selected = catalog.resolve_launch_recipe("service-a", "gen-a", "hermes-serve-v1")
    assert selected.process_start_target == "fixed-start-target"
    assert selected.cwd == roots[2]
    assert dict(selected.parameter_schema.validate({"profile": "production"})) == {"profile": "production"}
    with pytest.raises(EnrollmentDenied):
        catalog.resolve_launch_recipe("service-a", "gen-a", "caller-operation")


def test_managed_profile_conversion_carries_root_ids_and_selection_recipes(monkeypatch):
    item = {
        "enrollment_id": "service-a", "generation": "gen-a", "profile_id": "profile-a",
        "principal_id": "principal-a", "service_uid": 1001, "service_gid": 1001,
        "service_user": "hermes-owner", "device_enrollment_id": None,
        "expected_device_generation": None, "executable": "/opt/hermes/bin/hermes",
        "executable_sha256": "a" * 64, "runtime_artifact_ids": ["runtime-v1"],
        "package_runtime_records": {},
        "roots": {"home_id": "home-a", "work_id": "work-a", "data_id": "data-a",
                  "home": "/var/lib/hermes/home-a", "work": "/var/lib/hermes/work-a",
                  "data": "/var/lib/hermes/data-a"},
        "authority_endpoint_id": "socket-a", "namespace_identity": "ns-a",
        "socket_policy_id": "sockets-a", "target_route_ids": [],
        "operation_targets": {"process.start": "fixed-start-target"},
        "operation_recipes": {"hermes-server-start": launch_recipe("data-a")},
        "argv_recipe": ["serve"], "environment": {}, "max_lifetime_seconds": 600,
        "memory_max_bytes": 1000000, "cpu_quota_percent": 100, "io_weight": 100,
    }
    profile = _parse_profile(item)
    monkeypatch.setattr(type(profile.roots), "validate", lambda _self, **_kwargs: None)
    managed = profile.as_managed_profile(artifact_root=Path("/var/lib/hermes/artifacts"),
                                         child_artifact_refs={})
    assert (managed.enrollment_id, managed.home_id, managed.work_id, managed.data_id) == (
        "service-a", "home-a", "work-a", "data-a")
    assert (managed.home_root, managed.work_root, managed.data_root) == (
        profile.roots.home, profile.roots.work, profile.roots.data)
    assert managed.operation_recipes["hermes-server-start"]["cwd_root_id"] == "data-a"
    assert managed.operation_targets["process.start"] == "fixed-start-target"


def test_signed_manifest_hash_canonicalization_is_stable():
    unsigned = {"schema": 1, "records": []}
    reversed_order = {"records": [], "schema": 1}
    assert hashlib.sha256(_canonical(unsigned)).digest() == hashlib.sha256(_canonical(reversed_order)).digest()


def test_root_journal_resolution_is_digest_bound_and_rechecks_pinned_inode(tmp_path, monkeypatch):
    import hermes_installer.protected_enrollment as protected

    root = tmp_path / "authority-journal"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    info = root.stat()
    row = {
        "root_id": "installer-authority-journal-v1",
        "absolute_path": str(root), "owner_uid": 0, "owner_gid": 0,
        "mode": 0o700, "device": info.st_dev, "inode": info.st_ino,
        "generation": "journal-gen-a", "purpose": "authority-journal",
    }
    catalog = ProtectedRootJournalCatalog.from_protected_records(
        [row], generation_digest="a" * 64)

    def trusted_fixture_path(path, *, uid, directory):
        assert uid == 0 and directory is True
        return path

    monkeypatch.setattr(protected, "_owned_path", trusted_fixture_path)
    original_stat = Path.stat

    def root_owned_stat(path, *args, **kwargs):
        actual = original_stat(path, *args, **kwargs)
        if path == root:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_gid=0,
                                   st_dev=actual.st_dev, st_ino=actual.st_ino)
        return actual

    monkeypatch.setattr(Path, "stat", root_owned_stat)
    with pytest.raises(EnrollmentDenied, match="stale active generation"):
        catalog.resolve("installer-authority-journal-v1",
                        expected_active_generation_digest="b" * 64)
    selected = catalog.resolve("installer-authority-journal-v1",
                               expected_active_generation_digest="a" * 64)
    assert selected.path == root
    assert selected.inode == info.st_ino
    assert selected.service_generation_digest == "a" * 64

    monkeypatch.setattr(Path, "stat", lambda path, *args, **kwargs:
                        SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_gid=0,
                                        st_dev=info.st_dev, st_ino=info.st_ino + 1)
                        if path == root else original_stat(path, *args, **kwargs))
    with pytest.raises(EnrollmentDenied, match="identity changed"):
        catalog.resolve("installer-authority-journal-v1",
                        expected_active_generation_digest="a" * 64)
