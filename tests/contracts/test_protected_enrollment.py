from __future__ import annotations

import hashlib
import json
import os
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
    _canonical,
    _parse_profile,
)


def build_record(target="coral-cpython-build:start"):
    return {
        "target_id": target,
        "generation": "g1",
        "source_artifact_id": "source-v1",
        "source_sha256": "1" * 64,
        "toolchain_artifact_id": "toolchain-v1",
        "toolchain_sha256": "2" * 64,
        "builder_artifact_id": "builder-v1",
        "builder_sha256": "3" * 64,
        "argv_recipe": ["/opt/hermes/build-driver", "--profile", "coral-cpython-build"],
        "environment": {"PATH": "/opt/hermes/bin", "LANG": "C.UTF-8"},
        "max_lifetime_seconds": 600,
        "output_root_id": "coral-build-staging",
        "output_root": "/var/lib/hermes-installer/builds/coral",
        "output_owner_uid": 1001,
        "required_outputs": {"python/bin/python3.9": "4" * 64},
    }


def launch_recipe(root_id="data"):
    return {
        "executable_artifact_id": "runtime-v1", "executable_sha256": "a" * 64,
        "argv_recipe": [{"literal": "serve"}], "cwd_root_id": root_id, "cwd_subpath": "",
        "environment": {}, "child_artifact_refs": {}, "max_lifetime_seconds": 600,
        "max_output_bytes": 4096, "stdin_mode": "closed", "parameter_schema_id": "empty-params-v1",
    }


def test_build_target_is_fixed_and_generation_bound():
    catalog = ProtectedBuildCatalog.from_protected_records([build_record()])
    assert catalog.resolve("coral-cpython-build:start", "g1").builder_sha256 == "3" * 64
    with pytest.raises(EnrollmentDenied):
        catalog.resolve("colibri-source-build:start", "g1")
    with pytest.raises(EnrollmentDenied):
        catalog.resolve("coral-cpython-build:start", "g2")
    with pytest.raises(EnrollmentDenied):
        catalog.resolve("/tmp/attacker-script", "g1")


def test_fixed_build_record_rejects_unlisted_target_and_caller_recipe_fields():
    item = build_record("arbitrary-shell:start")
    with pytest.raises(EnrollmentDenied):
        FixedBuildProfile.from_protected_record(item)
    item = build_record()
    item["argv_recipe"] = ["/bin/sh", "-c", "{caller_command}"]
    with pytest.raises(EnrollmentDenied):
        FixedBuildProfile.from_protected_record(item)


def test_output_attestation_rejects_caller_path_and_wrong_bytes(tmp_path: Path, monkeypatch):
    record = build_record()
    output = tmp_path / "output"
    output.mkdir()
    (output / "python").mkdir()
    (output / "python" / "bin").mkdir()
    output.chmod(0o700)
    (output / "python").chmod(0o700)
    (output / "python" / "bin").chmod(0o700)
    (output / "python" / "bin" / "python3.9").write_bytes(b"unattested")
    profile = FixedBuildProfile.from_protected_record({**record, "output_root": str(output), "output_owner_uid": os.geteuid()})
    with pytest.raises(EnrollmentDenied, match="caller-selected"):
        profile.attest_outputs(tmp_path)
    original_lstat = Path.lstat
    def root_attested_lstat(path):
        result = original_lstat(path)
        # Model a root-owned non-writable ancestor chain while keeping the
        # temporary output leaf service-owned, matching the on-host custody
        # contract without weakening the production validator.
        if path == output or output in path.parents:
            owner = os.geteuid()
        else:
            owner = 0
        return SimpleNamespace(st_mode=result.st_mode & ~0o022, st_uid=owner)
    monkeypatch.setattr(Path, "lstat", root_attested_lstat)
    with pytest.raises(EnrollmentDenied, match="does not match"):
        profile.attest_outputs()


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
            "generation": profile.generation,
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


def test_memory_connector_route_binds_variant_port_and_exact_route():
    item = {
        "enrollment_id": "memory-service", "generation": "service-g1", "profile_id": "memory-profile",
        "principal_id": "memory-owner", "service_uid": 1001, "service_gid": 1001,
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
        fixed_route_map={"claude-postgres-search": {
            "method": "POST", "path": "/v1/search", "body": {"type": "object"}}},
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
    assert route.route_record["path"] == "/v1/search"
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


def test_signed_manifest_hash_canonicalization_is_stable():
    unsigned = {"schema": 1, "records": []}
    reversed_order = {"records": [], "schema": 1}
    assert hashlib.sha256(_canonical(unsigned)).digest() == hashlib.sha256(_canonical(reversed_order)).digest()
