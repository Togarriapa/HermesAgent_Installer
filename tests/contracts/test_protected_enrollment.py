from __future__ import annotations

import hashlib
import json
import stat
from types import SimpleNamespace
from pathlib import Path

import pytest

from hermes_installer.protected_enrollment import (
    EnrollmentDenied,
    FixedBuildProfile,
    OperationParameterSchema,
    ProtectedBuildCatalog,
    ProtectedDeviceCatalog,
    ProtectedEnrollmentCatalog,
    ProtectedRootJournalCatalog,
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
        "generation": profile.generation, "source_revision": "rev-1",
        "source_tree_sha256": "b" * 64,
        "compiled_closure_artifact_id": "compiled-closure", "compiled_closure_sha256": "c" * 64,
        "entrypoint_artifact_id": "plugin-entrypoint", "entrypoint_sha256": "d" * 64,
        "resolver_artifact_id": "plugin-resolver", "resolver_sha256": "e" * 64,
        "service_package_root_id": "desktop-package-root", "service_mount_id": "desktop-package-mount",
        "adapter_records": [{
            "adapter_id": "adapter-one", "manifest_sha256": "f" * 64,
            "adapter_artifact_id": "adapter-one-artifact", "adapter_sha256": "0" * 64,
            "action_id": "read", "argument_schema_id": "read-input-v1", "result_schema_id": "read-result-v1",
            "effect_enrollment_id": "effect-enrollment", "operation": "plugin.example.read",
            "capability": "example-read", "target_id": "example-target", "recipient": "example-recipient",
            "generation": profile.generation, "observer_enrollment_ids": [], "workflow_bindings": [],
        }],
    }
    catalog = ProtectedEnrollmentCatalog({("install-1", "gen-1"): profile}, digest="0" * 64,
                                         native_packages=[record])
    monkeypatch.setattr(catalog, "resolve", lambda enrollment_id, generation: profile
                        if (enrollment_id, generation) == ("install-1", "gen-1")
                        else (_ for _ in ()).throw(EnrollmentDenied("stale")))
    resolved = catalog.resolve_native_package("desktop-native", profile.generation)
    assert resolved.service_mount_id == "desktop-package-mount"
    assert resolved.adapter_records["adapter-one"].operation == "plugin.example.read"
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
        "generation": profile.generation, "source_revision": "rev-1",
        "source_tree_sha256": "b" * 64,
        "compiled_closure_artifact_id": "compiled-closure", "compiled_closure_sha256": "c" * 64,
        "entrypoint_artifact_id": "plugin-entrypoint", "entrypoint_sha256": "d" * 64,
        "resolver_artifact_id": "plugin-resolver", "resolver_sha256": "e" * 64,
        "service_package_root_id": "desktop-package-root", "service_mount_id": "desktop-package-mount",
        "adapter_records": [{
            "adapter_id": "adapter-one", "manifest_sha256": "f" * 64,
            "adapter_artifact_id": "adapter-one-artifact", "adapter_sha256": "0" * 64,
            "action_id": "read", "argument_schema_id": "read-input-v1", "result_schema_id": "read-result-v1",
            "effect_enrollment_id": "effect-enrollment", "operation": "plugin.example.read",
            "capability": "example-read", "target_id": "example-target", "recipient": "example-recipient",
            "generation": profile.generation, "observer_enrollment_ids": ["observer-one"],
            "workflow_bindings": [],
        }],
    }
    issuer = SourceIssuerRecord(
        "tool-result", profile.profile_id, "adapter-one-artifact", "0" * 64,
        "read-result-v1", (), profile.generation, "observer-one", ("registered-tool-result",),
    )
    catalog = ProtectedEnrollmentCatalog({("install-1", "gen-1"): profile}, digest="0" * 64,
                                         native_packages=[package], source_issuers=[issuer])
    join = catalog.source_observer_joins["observer-one"]
    assert join.issuer is issuer
    assert join.package.package_id == "desktop-native"
    assert join.adapter.adapter_id == "adapter-one"

    with pytest.raises(EnrollmentDenied, match="does not match"):
        ProtectedEnrollmentCatalog({("install-1", "gen-1"): profile}, digest="0" * 64,
                                   native_packages=[package], source_issuers=[
            SourceIssuerRecord("tool-result", profile.profile_id, "different-role", "0" * 64,
                               "read-result-v1", (), profile.generation, "observer-one",
                               ("registered-tool-result",))
        ])


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
