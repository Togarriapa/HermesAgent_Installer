"""Closed constructor and descriptor-reader contracts for active PM custody."""
from __future__ import annotations

import os

import pytest

from hermes_installer.authority.active_native_worker_runtime import (
    ActiveNativeWorkerRuntimeUnavailable,
    RootActiveNativeWorkerRuntimeRegistry,
    _native_output_relative_parts,
    _read_fd,
    _validate_source_member_catalog,
)


def test_active_runtime_registry_rejects_untyped_runtime_and_owner():
    with pytest.raises(ActiveNativeWorkerRuntimeUnavailable):
        RootActiveNativeWorkerRuntimeRegistry.from_root_runtime(object(), object())


def test_protected_receipt_reader_enforces_its_size_bound(tmp_path):
    path = tmp_path / "receipt.json"
    path.write_bytes(b"{}")
    fd = os.open(path, os.O_RDONLY)
    try:
        assert _read_fd(fd, 2) == b"{}"
    finally:
        os.close(fd)
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="size bound"):
            _read_fd(fd, 1)
    finally:
        os.close(fd)


@pytest.mark.parametrize("path", [
    "../escape/file.py",
    "native-compiled-closure/../../etc/passwd",
    "native-action-resolver//resolver.py",
    r"native-boundary-overlay\patch.py",
    "/native-candidate-index/index.json",
])
def test_active_output_member_path_is_confined_to_fixed_role_root(path):
    with pytest.raises(ValueError):
        _native_output_relative_parts(path)


def test_active_output_member_accepts_nested_role_relative_path():
    assert _native_output_relative_parts(
        "native-compiled-closure/pkg/module.py") == (
            "native-compiled-closure", "pkg", "module.py")


def test_source_member_catalog_requires_sorted_exact_unique_handles():
    rows = [{
        "artifact_id": "installer-module:example.adapter",
        "receipt_handle": "receipt-b",
        "relative_path": "lib/python/example/adapter.py",
        "kind": "regular-file",
        "sha256": "a" * 64,
        "size_bytes": 12,
        "mode": 0o444,
        "owner_uid": 0,
        "owner_gid": 0,
        "device": 1,
        "inode": 2,
        "link_target": None,
        "output_role": None,
    }]
    with pytest.raises(ValueError, match="handles"):
        _validate_source_member_catalog(rows, ())
    with pytest.raises(ValueError, match="join"):
        _validate_source_member_catalog(rows, ("receipt-a",))
    with pytest.raises(ValueError, match="malformed"):
        _validate_source_member_catalog([{**rows[0], "unexpected": True}], ("receipt-b",))


def test_source_member_catalog_checks_sorted_all_member_receipts():
    rows = []
    for artifact, handle, path in (
        ("installer-module:a", "z-receipt", "lib/python/a.py"),
        ("installer-module:b", "a-receipt", "lib/python/b.py"),
    ):
        rows.append({
            "artifact_id": artifact, "receipt_handle": handle, "relative_path": path,
            "kind": "regular-file", "sha256": "b" * 64, "size_bytes": 1,
            "mode": 0o444, "owner_uid": 0, "owner_gid": 0, "device": 1,
            "inode": 2, "link_target": None, "output_role": None,
        })
    _validate_source_member_catalog(rows, ("a-receipt", "z-receipt"))
