"""Contract tests for path-free PM receipts and exact-current resolution."""
import json
import os
import stat
from types import SimpleNamespace
from pathlib import Path

import pytest

from hermes_installer.authority import pm_runtime


class SessionStore:
    def _live(self, handle):
        return object()


class SetupSession:
    def __init__(self):
        from types import SimpleNamespace
        self._factory = SimpleNamespace(session_store=SessionStore())
        self._handle = object()
        self._last_receipt = None
    def _check_live(self):
        return None


def _receipt(root: Path, *, runtime_sha=None):
    handle = "H" * 48
    generation = "pm-" + "a" * 32
    executable = root / generation / "hermes-home/installs/fixture/environments/one/bin/python"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"runtime fixture")
    executable.chmod(0o700)
    os.chmod(executable.parent, 0o700)
    st = executable.stat()
    rec = {
        "schema": 1, "receipt_id": "pm-runtime-fixture", "handle": handle,
        "setup_session_id": "setup-fixture", "transaction_handle": "transaction-fixture",
        "prepared_generation_id": "generation-fixture",
        "source_commit": pm_runtime.SOURCE_COMMIT,
        "source_receipt_handle": "S" * 48,
        "pm_lock_artifact_id": pm_runtime.LOCK_ID, "pm_lock_sha256": pm_runtime.LOCK_SHA256,
        "uv_artifact_id": pm_runtime.UV_ID, "uv_sha256": pm_runtime.UV_SHA256,
        "base_python_artifact_id": pm_runtime.PYTHON_ID, "base_python_sha256": pm_runtime.PYTHON_SHA256,
        "pm_sync_outcome": "succeeded", "runtime_relative": "hermes-home/installs/fixture/environments/one/bin/python",
        "runtime_venv_relative": "hermes-home/installs/fixture/environments/one",
        "runtime_closure_sha256": pm_runtime._tree_sha256(executable.parent.parent),
        "runtime_executable_sha256": runtime_sha or pm_runtime._hash(executable),
        "runtime_device": st.st_dev, "runtime_inode": st.st_ino, "runtime_uid": st.st_uid,
        "runtime_gid": st.st_gid, "runtime_mode": stat.S_IMODE(st.st_mode),
        "version_info": [3, 14, 7], "implementation": "cpython", "cache_tag": "cpython-314",
        "soabi": "cpython-314-aarch64-linux-gnu", "machine": "aarch64",
        "generation": generation, "expires_monotonic": 9999999999,
    }
    receipt_dir = root / "receipts"
    receipt_dir.mkdir(mode=0o700)
    (receipt_dir / f"{handle}.json").write_text(json.dumps(rec), encoding="utf-8")
    (receipt_dir / f"{handle}.json").chmod(0o600)
    return handle, executable, rec


def _identity(path: Path, rec):
    return {
        "sha256": pm_runtime._hash(path), "device": rec["runtime_device"],
        "inode": rec["runtime_inode"], "uid": rec["runtime_uid"], "gid": rec["runtime_gid"],
        "mode": rec["runtime_mode"], "version_info": (3, 14, 7),
        "implementation": "cpython", "cache_tag": "cpython-314",
        "soabi": "cpython-314-aarch64-linux-gnu", "machine": "aarch64",
    }


def _registry(monkeypatch, root, guard=lambda transaction, generation: True):
    monkeypatch.setattr(pm_runtime, "_require_root_linux", lambda: None)
    original_lstat = Path.lstat
    def owned_lstat(path):
        value = original_lstat(path)
        if path.parent == root / "receipts":
            return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_gid=0, st_nlink=1)
        return value
    monkeypatch.setattr(Path, "lstat", owned_lstat)
    monkeypatch.setattr(pm_runtime, "_observe_runtime", lambda path, expected_uid, expected_root: _identity(path, _REC))
    return pm_runtime.RootPMRuntimeReceiptRegistry(
        runtime_root=root, setup_session=SetupSession(), current_guard=guard,
        monotonic=lambda: 50.0)


_REC = {}


def test_resolver_returns_only_root_private_verified_interpreter(tmp_path, monkeypatch):
    global _REC
    handle, executable, _REC = _receipt(tmp_path)
    resolver = _registry(monkeypatch, tmp_path)

    selected = resolver.resolve_runtime(handle, "transaction-fixture", "generation-fixture")

    assert selected.python_path == executable
    assert selected.runtime_sha256 == pm_runtime._hash(executable)
    assert selected.version_info[:2] == (3, 14)


def test_resolver_rejects_current_generation_drift(tmp_path, monkeypatch):
    global _REC
    handle, _, _REC = _receipt(tmp_path)
    resolver = _registry(monkeypatch, tmp_path, guard=lambda *_: False)

    with pytest.raises(pm_runtime.BootstrapEnrollmentError, match="stale"):
        resolver.resolve_runtime(handle, "transaction-fixture", "generation-fixture")


def test_resolver_rejects_runtime_byte_substitution(tmp_path, monkeypatch):
    global _REC
    handle, executable, rec = _receipt(tmp_path)
    executable.write_bytes(b"substituted")
    _REC = rec
    resolver = _registry(monkeypatch, tmp_path)

    with pytest.raises(pm_runtime.BootstrapEnrollmentError, match="identity changed"):
        resolver.resolve_runtime(handle, "transaction-fixture", "generation-fixture")


def test_receipt_contains_no_absolute_path_and_rejects_wrong_setup_join(tmp_path, monkeypatch):
    global _REC
    handle, _, _REC = _receipt(tmp_path)
    resolver = _registry(monkeypatch, tmp_path)
    record = resolver._record(handle)
    assert not any(isinstance(value, str) and value.startswith("/") for value in record.values())
    with pytest.raises(pm_runtime.BootstrapEnrollmentError, match="another setup"):
        resolver.resolve_runtime(handle, "other-transaction", "generation-fixture")
