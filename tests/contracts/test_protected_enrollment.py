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
    ProtectedBuildCatalog,
    ProtectedDeviceCatalog,
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
        if path == output or output in path.parents:
            return SimpleNamespace(st_mode=result.st_mode, st_uid=os.geteuid())
        return SimpleNamespace(st_mode=result.st_mode, st_uid=0)
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


def test_profile_rejects_caller_selected_roots_and_malformed_recipe():
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
        "argv_recipe": ["/opt/hermes/bin/hermes", "serve"], "environment": {"HOME": "/var/lib/hermes/home"},
        "max_lifetime_seconds": 600, "memory_max_bytes": 1000000,
        "cpu_quota_percent": 100, "io_weight": 100,
    }
    parsed = _parse_profile(item)
    assert parsed.roots.home != parsed.roots.work != parsed.roots.data
    with pytest.raises(EnrollmentDenied):
        _parse_profile({**item, "roots": {**item["roots"], "data": "/tmp/caller-root"}, "argv": ["bad"]})


def test_signed_manifest_hash_canonicalization_is_stable():
    unsigned = {"schema": 1, "records": []}
    reversed_order = {"records": [], "schema": 1}
    assert hashlib.sha256(_canonical(unsigned)).digest() == hashlib.sha256(_canonical(reversed_order)).digest()
