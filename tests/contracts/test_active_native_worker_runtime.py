"""Closed constructor and descriptor-reader contracts for active PM custody."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from hermes_installer.authority.active_native_worker_runtime import (
    ActiveNativeWorkerRuntimeUnavailable,
    RootActiveNativeWorkerRuntimeRegistry,
    _native_output_relative_parts,
    _read_fd,
    _validate_source_member_catalog,
    _ProjectionFDCustody,
    RootActiveNativeWorkerRuntimeProjection,
)
from hermes_installer.authority.active_native_worker_runtime import RootActiveNativeWorkerRuntimeRegistry
from hermes_installer.authority import pm_runtime


def test_projection_fd_custody_is_idempotent_after_numeric_fd_reuse():
    read_fd, write_fd = os.pipe()
    owner = object.__new__(RootActiveNativeWorkerRuntimeRegistry)
    owner._issued = {}
    owner._network_inputs = {}
    projection = RootActiveNativeWorkerRuntimeProjection(
        projection_handle="projection", network_projection_handle="network",
        service_generation_digest="a" * 64, runtime_record_id="runtime",
        runtime_record_sha256="b" * 64, pm_runtime_receipt_handle="pm",
        pm_runtime_root_device=1, pm_runtime_root_inode=2,
        pm_venv_root_path=Path("/private/selected/venv"),
        pm_venv_root_device=3, pm_venv_root_inode=4,
        pm_base_root_path=Path("/private/selected/base"),
        pm_base_root_device=5, pm_base_root_inode=6,
        native_output_root_device=7, native_output_root_inode=8,
        native_output_root_path=Path("/private/selected/output"),
        native_output_root_receipt_handle="receipt-output",
        native_output_root_receipt_sha256="c" * 64,
        expires_monotonic=float("inf"), member_fds=(read_fd,),
        _custody=_ProjectionFDCustody((read_fd,)), _owner=owner, _issuer=object(),
    )
    owner._issued[projection.projection_handle] = projection
    owner._network_inputs[projection.projection_handle] = object()
    projection.close()
    assert "projection" not in owner._issued
    assert "projection" not in owner._network_inputs
    reused_fd = os.open("/dev/null", os.O_RDONLY)
    try:
        assert reused_fd == read_fd
        projection.close()
        os.fstat(reused_fd)
    finally:
        os.close(reused_fd)
        os.close(write_fd)


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


def test_committed_pm_venv_observation_holds_and_hashes_full_tree(tmp_path, monkeypatch):
    root = tmp_path / "venv"
    package = root / "lib" / "python3.14" / "site-packages"
    package.mkdir(parents=True)
    executable = root / "bin" / "python3.14"
    executable.parent.mkdir()
    executable.write_bytes(b"fixed interpreter bytes")
    executable.chmod(0o555)
    module = package / "worker.py"
    module.write_bytes(b"fixed dependency bytes")
    module.chmod(0o444)
    for directory in (root, root / "bin", root / "lib", root / "lib" / "python3.14", package):
        directory.chmod(0o555)
    # The fixture is controlled test data on the development host, not root
    # custody evidence. Actual root ownership is still enforced in production.
    monkeypatch.setattr(pm_runtime, "_root_owned", lambda _info: True)
    expected = pm_runtime._tree_sha256(root)
    observed = pm_runtime.observe_committed_pm_venv_tree(
        root, expected_closure_sha256=expected,
    )
    try:
        assert observed.closure_sha256 == expected
        assert observed.root_inode == root.stat().st_ino
        assert {item.relative_path for item in observed.members} == {
            "bin/python3.14", "lib/python3.14/site-packages/worker.py",
        }
        executable_member = next(item for item in observed.members
                                 if item.relative_path == "bin/python3.14")
        assert executable_member.sha256 == pm_runtime._hash(executable)
        assert executable_member.fd is not None
    finally:
        observed.close()


def test_committed_pm_venv_observation_rejects_changed_closure_and_escape(tmp_path, monkeypatch):
    root = tmp_path / "venv"
    root.mkdir()
    executable = root / "python"
    executable.write_bytes(b"interpreter")
    executable.chmod(0o555)
    root.chmod(0o555)
    monkeypatch.setattr(pm_runtime, "_root_owned", lambda _info: True)
    expected = pm_runtime._tree_sha256(root)
    executable.chmod(0o755)
    executable.write_bytes(b"changed interpreter")
    with pytest.raises(ValueError, match="closure"):
        pm_runtime.observe_committed_pm_venv_tree(root, expected_closure_sha256=expected)
    root.chmod(0o755)
    outside = tmp_path / "outside"
    outside.write_bytes(b"must never be opened through the link")
    outside.chmod(0o444)
    escape = root / "escape"
    escape.symlink_to("../outside")
    link_mode = stat.S_IMODE(escape.lstat().st_mode)
    outside_info = outside.stat()
    real_open = pm_runtime.os.open
    link_open_flags = []

    def guarded_open(path, flags, *args, **kwargs):
        if os.fspath(path) == os.fspath(outside):
            raise AssertionError("observer attempted to open the outside target")
        if os.fspath(path) == "escape":
            link_open_flags.append(flags)
            assert flags & getattr(os, "O_NOFOLLOW", 0), "link target must never be followed"
        descriptor = real_open(path, flags, *args, **kwargs)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) == (outside_info.st_dev, outside_info.st_ino):
            os.close(descriptor)
            raise AssertionError("observer opened the outside target through a link")
        return descriptor

    monkeypatch.setattr(pm_runtime.os, "open", guarded_open)
    # Linux reports symlink mode 0777. The observer intentionally rejects
    # that unsafe mode before it inspects the target; other hosts may reach
    # the explicit in-root-link check instead.
    expected_denial = ("ownership or mode is unsafe" if link_mode & 0o022
                       else "link escapes its root")
    with pytest.raises(ValueError, match=expected_denial):
        pm_runtime.observe_committed_pm_venv_tree(
            root, expected_closure_sha256=pm_runtime._tree_sha256(root),
        )
    assert not link_open_flags or all(
        flags & getattr(os, "O_NOFOLLOW", 0) for flags in link_open_flags
    )
    assert outside.read_bytes() == b"must never be opened through the link"


def test_active_descriptor_must_equal_actual_receipt_executable_and_full_venv(tmp_path, monkeypatch):
    base = tmp_path / "pm-generation"
    venv = base / "hermes" / ".venv"
    executable = venv / "bin" / "python3.14"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"observed interpreter")
    executable.chmod(0o555)
    for directory in (base, base / "hermes", venv, venv / "bin"):
        directory.mkdir(exist_ok=True)
        directory.chmod(0o555)
    monkeypatch.setattr(pm_runtime, "_root_owned", lambda _info: True)
    info = executable.stat()
    receipt = {
        "handle": "receipt-handle", "generation": "pm-" + "a" * 32,
        "source_commit": "official-source", "runtime_relative": "hermes/.venv/bin/python3.14",
        "runtime_venv_relative": "hermes/.venv",
        "runtime_closure_sha256": pm_runtime._tree_sha256(venv),
    }
    import hashlib
    raw = b"the exact retained protected PM receipt bytes"
    identity = {
        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
        "gid": info.st_gid, "mode": info.st_mode & 0o777,
    }
    descriptor = {
        "schema": 1, "identity_kind": "pm-committed-hermes-venv-v1",
        "pm_runtime_receipt_handle": receipt["handle"],
        "pm_receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "pm_generation": receipt["generation"], "source_commit": receipt["source_commit"],
        "runtime_relative": receipt["runtime_relative"],
        "runtime_venv_relative": receipt["runtime_venv_relative"],
        "runtime_closure_sha256": receipt["runtime_closure_sha256"],
        "executable_identity_id": "observed:pm-committed-venv-python",
        "executable_sha256": identity["sha256"], "executable_device": info.st_dev,
        "executable_inode": info.st_ino, "executable_uid": info.st_uid,
        "executable_gid": info.st_gid, "executable_mode": info.st_mode & 0o777,
    }
    fds = []
    RootActiveNativeWorkerRuntimeRegistry._match_committed_venv_identity(
        {"committed_venv_identity": descriptor}, receipt, raw, identity, base, fds,
    )
    assert len(fds) == 2  # held venv root plus exact selected executable
    for fd in fds:
        os.close(fd)
    descriptor["executable_inode"] += 1
    with pytest.raises(ValueError, match="descriptor"):
        RootActiveNativeWorkerRuntimeRegistry._match_committed_venv_identity(
            {"committed_venv_identity": descriptor}, receipt, raw, identity, base, [],
        )
