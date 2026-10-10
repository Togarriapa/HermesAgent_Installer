"""Contract tests for path-free PM receipts and exact-current resolution."""
import hashlib
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
        self._authorization = SimpleNamespace(transaction_handle="transaction-fixture")
    def _check_live(self):
        return None
    def _refresh_authorization(self):
        return None


def _base_runtime(root: Path):
    artifact_root = root / "artifact-root"
    base = artifact_root / "trees" / pm_runtime.PYTHON_ID / pm_runtime.PYTHON_SHA256 / "content"
    executable = base / "bin/python3.14"
    stdlib = base / "lib/python3.14/os.py"
    executable.parent.mkdir(parents=True)
    stdlib.parent.mkdir(parents=True)
    executable.write_bytes(b"official python executable fixture")
    stdlib.write_bytes(b"stdlib module fixture")
    executable.chmod(0o555)
    stdlib.chmod(0o444)
    link = base / "bin/python3"
    link.symlink_to("python3.14")
    for directory in (stdlib.parent, executable.parent, base / "lib", base):
        directory.chmod(0o555)
    rows = (
        SimpleNamespace(path="bin/python3.14", sha256=pm_runtime._hash(executable),
                        size_bytes=executable.stat().st_size, executable=True,
                        kind="file", link_target=None),
        SimpleNamespace(path="bin/python3", sha256=hashlib.sha256(b"python3.14").hexdigest(),
                        size_bytes=len(b"python3.14"), executable=False,
                        kind="symlink", link_target="python3.14"),
        SimpleNamespace(path="lib/python3.14/os.py", sha256=pm_runtime._hash(stdlib),
                        size_bytes=stdlib.stat().st_size, executable=False,
                        kind="file", link_target=None),
    )
    return artifact_root, base, rows, pm_runtime._tree_sha256(base), pm_runtime._hash(executable)


def _uv_runtime(artifact_root: Path):
    base = artifact_root / "trees" / pm_runtime.UV_ID / pm_runtime.UV_SHA256 / "content"
    base.mkdir(parents=True)
    executable = base / "uv"
    companion = base / "uvx"
    executable.write_bytes(b"official uv fixture")
    companion.write_bytes(b"official uvx fixture")
    executable.chmod(0o555)
    companion.chmod(0o555)
    base.chmod(0o555)
    rows = (
        SimpleNamespace(path="uv", sha256=pm_runtime._hash(executable),
                        size_bytes=executable.stat().st_size, executable=True,
                        kind="file", link_target=None),
        SimpleNamespace(path="uvx", sha256=pm_runtime._hash(companion),
                        size_bytes=companion.stat().st_size, executable=True,
                        kind="file", link_target=None),
    )
    return base, rows, pm_runtime._tree_sha256(base), pm_runtime._hash(executable)


def _receipt(root: Path, *, runtime_sha=None, base_runtime=None):
    handle = "H" * 48
    generation = "pm-" + "a" * 32
    executable = root / generation / "hermes-home/installs/fixture/environments/one/bin/python"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"runtime fixture")
    executable.chmod(0o700)
    os.chmod(executable.parent, 0o700)
    st = executable.stat()
    if base_runtime is None:
        base_runtime = _base_runtime(root)
    artifact_root, base_tree, _rows, base_closure_sha, base_executable_sha = base_runtime
    uv_tree, uv_rows, uv_closure_sha, uv_executable_sha = _uv_runtime(artifact_root)
    rec = {
        "schema": 1, "receipt_id": "pm-runtime-fixture", "handle": handle,
        "setup_session_id": "setup-fixture", "transaction_handle": "transaction-fixture",
        "prepared_generation_id": "generation-fixture",
        "source_commit": pm_runtime.SOURCE_COMMIT,
        "source_receipt_handle": "S" * 48,
        "pm_lock_artifact_id": pm_runtime.LOCK_ID, "pm_lock_sha256": pm_runtime.LOCK_SHA256,
        "uv_artifact_id": pm_runtime.UV_ID, "uv_sha256": pm_runtime.UV_SHA256,
        "uv_source_receipt_handle": "U" * 48,
        "uv_tree_relative": uv_tree.relative_to(artifact_root).as_posix(),
        "uv_tree_closure_sha256": uv_closure_sha,
        "uv_executable_relative": "uv", "uv_executable_sha256": pm_runtime.UV_EXECUTABLE_SHA256,
        "base_python_artifact_id": pm_runtime.PYTHON_ID, "base_python_sha256": pm_runtime.PYTHON_SHA256,
        "pm_sync_outcome": "succeeded", "runtime_relative": "hermes-home/installs/fixture/environments/one/bin/python",
        "runtime_venv_relative": "hermes-home/installs/fixture/environments/one",
        "runtime_closure_sha256": pm_runtime._tree_sha256(executable.parent.parent),
        "base_python_tree_relative": base_tree.relative_to(artifact_root).as_posix(),
        "base_python_closure_sha256": base_closure_sha,
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
    return handle, executable, rec, (artifact_root, base_tree, _rows, base_closure_sha,
                                     base_executable_sha, uv_tree, uv_rows, uv_closure_sha,
                                     uv_executable_sha)


def _identity(path: Path, rec):
    return {
        "sha256": pm_runtime._hash(path), "device": rec["runtime_device"],
        "inode": rec["runtime_inode"], "uid": rec["runtime_uid"], "gid": rec["runtime_gid"],
        "mode": rec["runtime_mode"], "version_info": (3, 14, 7),
        "implementation": "cpython", "cache_tag": "cpython-314",
        "soabi": "cpython-314-aarch64-linux-gnu", "machine": "aarch64",
    }


def _registry(monkeypatch, root, base_runtime, guard=lambda transaction, generation: True):
    monkeypatch.setattr(pm_runtime, "_require_root_linux", lambda: None)
    original_lstat = Path.lstat
    def owned_lstat(path):
        value = original_lstat(path)
        if path.parent == root / "receipts":
            return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_gid=0, st_nlink=1)
        return value
    monkeypatch.setattr(Path, "lstat", owned_lstat)
    monkeypatch.setattr(pm_runtime, "_observe_runtime", lambda path, expected_uid, expected_root: _identity(path, _REC))
    artifact_root, base_tree, rows, _closure_sha, _executable_sha, uv_tree, uv_rows, _uv_closure, _uv_sha = base_runtime
    catalog = SimpleNamespace(
        artifacts={
            pm_runtime.PYTHON_ID: SimpleNamespace(
                artifact_id=pm_runtime.PYTHON_ID, sha256=pm_runtime.PYTHON_SHA256, tree_files=rows),
            pm_runtime.UV_ID: SimpleNamespace(
                artifact_id=pm_runtime.UV_ID, sha256=pm_runtime.UV_SHA256, tree_files=uv_rows),
        },
        materialize_tree=lambda artifact_id, sha256, staging_root, expected_uid: SimpleNamespace(
            path=base_tree if artifact_id == pm_runtime.PYTHON_ID else uv_tree),
    )
    receipts = SimpleNamespace(
        catalog=catalog, artifact_root=artifact_root,
        lookup=lambda handle, proof: (pm_runtime.UV_ID, pm_runtime.UV_SHA256))
    session = SetupSession()
    return pm_runtime.RootPMRuntimeReceiptRegistry(
        runtime_root=root, setup_session=session, current_guard=guard,
        catalog=catalog, artifact_root=artifact_root,
        artifact_receipts=receipts,
        monotonic=lambda: 50.0)


_REC = {}


def test_resolver_returns_only_root_private_verified_interpreter(tmp_path, monkeypatch):
    global _REC
    handle, executable, _REC, base_runtime = _receipt(tmp_path)
    resolver = _registry(monkeypatch, tmp_path, base_runtime)

    selected = resolver.resolve_runtime(handle, "transaction-fixture", "generation-fixture")

    assert selected.python_path == executable
    assert selected.runtime_sha256 == pm_runtime._hash(executable)
    assert selected.version_info[:2] == (3, 14)


def test_resolver_rejects_current_generation_drift(tmp_path, monkeypatch):
    global _REC
    handle, _, _REC, base_runtime = _receipt(tmp_path)
    resolver = _registry(monkeypatch, tmp_path, base_runtime, guard=lambda *_: False)

    with pytest.raises(pm_runtime.BootstrapEnrollmentError, match="stale"):
        resolver.resolve_runtime(handle, "transaction-fixture", "generation-fixture")


def test_resolver_rejects_runtime_byte_substitution(tmp_path, monkeypatch):
    global _REC
    handle, executable, rec, base_runtime = _receipt(tmp_path)
    executable.write_bytes(b"substituted")
    _REC = rec
    resolver = _registry(monkeypatch, tmp_path, base_runtime)

    with pytest.raises(pm_runtime.BootstrapEnrollmentError, match="identity changed"):
        resolver.resolve_runtime(handle, "transaction-fixture", "generation-fixture")


def test_receipt_contains_no_absolute_path_and_rejects_wrong_setup_join(tmp_path, monkeypatch):
    global _REC
    handle, _, _REC, base_runtime = _receipt(tmp_path)
    resolver = _registry(monkeypatch, tmp_path, base_runtime)
    record = resolver._record(handle)
    assert not any(isinstance(value, str) and value.startswith("/") for value in record.values())
    with pytest.raises(pm_runtime.BootstrapEnrollmentError, match="another setup"):
        resolver.resolve_runtime(handle, "other-transaction", "generation-fixture")


def test_runtime_projection_holds_exact_readonly_python_and_stdlib_members(tmp_path, monkeypatch):
    import fcntl
    global _REC
    handle, _, _REC, base_runtime = _receipt(tmp_path)
    executable_sha = base_runtime[4]
    monkeypatch.setattr(pm_runtime, "PYTHON_EXECUTABLE_SHA256", executable_sha)
    monkeypatch.setattr(pm_runtime, "_root_owned", lambda info: (
        info.st_uid == os.getuid() and info.st_gid == os.getgid()))
    resolver = _registry(monkeypatch, tmp_path, base_runtime)

    projection = resolver.resolve_runtime_projection(
        handle, "transaction-fixture", "generation-fixture")
    try:
        assert projection.base_closure_sha256 == base_runtime[3]
        assert projection.executable_relative_path == "bin/python3.14"
        assert projection.executable_member.sha256 == executable_sha
        assert projection.executable_member.kind == "file"
        assert {row.relative_path for row in projection.members} == {
            "bin/python3", "bin/python3.14", "lib/python3.14/os.py"}
        assert [row.relative_path for row in projection.members] == sorted(
            row.relative_path for row in projection.members)
        assert [row.relative_path for row in projection.runtime_members] == [
            "bin/python3", "lib/python3.14/os.py"]
        executable_flags = fcntl.fcntl(projection.executable_member.fd, fcntl.F_GETFL)
        assert executable_flags & os.O_ACCMODE == os.O_RDONLY
        assert os.pread(projection.executable_member.fd, 100, 0) == b"official python executable fixture"
        module = next(row for row in projection.members if row.relative_path.endswith("/os.py"))
        assert os.pread(module.fd, 100, 0) == b"stdlib module fixture"
        alias = next(row for row in projection.members if row.kind == "symlink")
        assert alias.link_target == "python3.14"
        assert alias.sha256 == hashlib.sha256(b"python3.14").hexdigest()
    finally:
        projection.close()


def test_runtime_projection_rejects_base_closure_byte_and_symlink_drift(tmp_path, monkeypatch):
    global _REC
    handle, _, _REC, base_runtime = _receipt(tmp_path)
    monkeypatch.setattr(pm_runtime, "PYTHON_EXECUTABLE_SHA256", base_runtime[4])
    monkeypatch.setattr(pm_runtime, "_root_owned", lambda info: (
        info.st_uid == os.getuid() and info.st_gid == os.getgid()))
    resolver = _registry(monkeypatch, tmp_path, base_runtime)
    stdlib = base_runtime[1] / "lib/python3.14/os.py"
    stdlib.chmod(0o644)
    stdlib.write_bytes(b"changed stdlib")
    stdlib.chmod(0o444)
    with pytest.raises(pm_runtime.BootstrapEnrollmentError, match="closure"):
        resolver.resolve_runtime_projection(handle, "transaction-fixture", "generation-fixture")

    stdlib.chmod(0o644)
    stdlib.write_bytes(b"stdlib module fixture")
    stdlib.chmod(0o444)
    alias = base_runtime[1] / "bin/python3"
    alias.parent.chmod(0o755)
    alias.unlink()
    alias.symlink_to("../../escape")
    alias.parent.chmod(0o555)
    with pytest.raises(pm_runtime.BootstrapEnrollmentError, match="closure"):
        resolver.resolve_runtime_projection(handle, "transaction-fixture", "generation-fixture")


def test_runtime_projection_rejects_foreign_owned_tree(tmp_path, monkeypatch):
    global _REC
    handle, _, _REC, base_runtime = _receipt(tmp_path)
    monkeypatch.setattr(pm_runtime, "PYTHON_EXECUTABLE_SHA256", base_runtime[4])
    monkeypatch.setattr(pm_runtime, "_root_owned", lambda _info: False)
    resolver = _registry(monkeypatch, tmp_path, base_runtime)

    with pytest.raises(pm_runtime.BootstrapEnrollmentError, match="closure"):
        resolver.resolve_runtime_projection(handle, "transaction-fixture", "generation-fixture")


def test_uv_projection_is_receipt_bound_and_holds_exact_readonly_bytes(tmp_path, monkeypatch):
    global _REC
    handle, _, _REC, base_runtime = _receipt(tmp_path)
    uv_sha = base_runtime[8]
    monkeypatch.setattr(pm_runtime, "UV_EXECUTABLE_SHA256", uv_sha)
    _REC["uv_executable_sha256"] = uv_sha
    (tmp_path / "receipts" / f"{handle}.json").write_text(json.dumps(_REC), encoding="utf-8")
    (tmp_path / "receipts" / f"{handle}.json").chmod(0o600)
    monkeypatch.setattr(pm_runtime, "_root_owned", lambda info: (
        info.st_uid == os.getuid() and info.st_gid == os.getgid()))
    resolver = _registry(monkeypatch, tmp_path, base_runtime)

    projection = resolver.resolve_uv_tool(handle, "transaction-fixture", "generation-fixture")
    try:
        assert projection.receipt_handle == handle
        assert projection.source_receipt_handle == "U" * 48
        assert projection.artifact_id == pm_runtime.UV_ID
        assert projection.relative_path == "uv"
        assert projection.sha256 == uv_sha
        assert projection.size_bytes == len(b"official uv fixture")
        assert projection.mode == 0o555
        assert os.pread(projection.fd, 100, 0) == b"official uv fixture"
        resolver.verify_current_uv_tool(projection)
    finally:
        projection.close()


def test_uv_projection_rejects_wrong_source_receipt_and_changed_tree(tmp_path, monkeypatch):
    global _REC
    handle, _, _REC, base_runtime = _receipt(tmp_path)
    uv_sha = base_runtime[8]
    monkeypatch.setattr(pm_runtime, "UV_EXECUTABLE_SHA256", uv_sha)
    _REC["uv_executable_sha256"] = uv_sha
    (tmp_path / "receipts" / f"{handle}.json").write_text(json.dumps(_REC), encoding="utf-8")
    (tmp_path / "receipts" / f"{handle}.json").chmod(0o600)
    monkeypatch.setattr(pm_runtime, "_root_owned", lambda info: (
        info.st_uid == os.getuid() and info.st_gid == os.getgid()))
    resolver = _registry(monkeypatch, tmp_path, base_runtime)
    resolver.artifact_receipts.lookup = lambda *_: (pm_runtime.PYTHON_ID, pm_runtime.PYTHON_SHA256)
    with pytest.raises(pm_runtime.BootstrapEnrollmentError, match="source receipt"):
        resolver.resolve_uv_tool(handle, "transaction-fixture", "generation-fixture")

    resolver.artifact_receipts.lookup = lambda *_: (pm_runtime.UV_ID, pm_runtime.UV_SHA256)
    projection = resolver.resolve_uv_tool(handle, "transaction-fixture", "generation-fixture")
    uv = base_runtime[5] / "uv"
    uv.chmod(0o755)
    uv.write_bytes(b"changed uv fixture")
    uv.chmod(0o555)
    try:
        with pytest.raises(pm_runtime.BootstrapEnrollmentError, match="changed"):
            resolver.verify_current_uv_tool(projection)
    finally:
        projection.close()
