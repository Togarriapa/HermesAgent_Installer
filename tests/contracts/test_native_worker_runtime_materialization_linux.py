"""Root Linux filesystem effects for native output member custody."""
from __future__ import annotations

import hashlib
import fcntl
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from hermes_installer.authority.native_worker_runtime_materialization import (
    NativeWorkerRuntimeMaterializationUnavailable,
    RootPreparedNativeWorkerRuntimeMaterializationRegistry,
    _hash_fd,
)
from hermes_installer.authority.pm_runtime import _tree_sha256


@unittest.skipUnless(os.sys.platform.startswith("linux") and os.geteuid() == 0,
                     "requires an isolated Linux root fixture")
class NativeWorkerRuntimeMaterializationLinuxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="hermes-native-runtime-")
        self.parent = Path(self.temporary.name)
        os.chmod(self.parent, 0o700)
        self.parent_fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.leaf = "r" * 40
        os.mkdir(self.leaf, 0o700, dir_fd=self.parent_fd)
        self.root_fd = os.open(self.leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=self.parent_fd)
        self.registry = object.__new__(RootPreparedNativeWorkerRuntimeMaterializationRegistry)

    def tearDown(self) -> None:
        os.close(self.root_fd)
        os.close(self.parent_fd)
        self.temporary.cleanup()

    def test_materializes_actual_root_file_and_returns_held_inode_witness(self) -> None:
        content = b"verified native output\n"
        expected = SimpleNamespace(
            mode=0o444, size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        held: list[int] = []
        row = self.registry._write_member(
            self.root_fd, "native-action-resolver", "resolver.py", content, expected,
            "native-action-resolver-v1", "output-receipt", held)
        info = os.stat("native-action-resolver/resolver.py", dir_fd=self.root_fd,
                       follow_symlinks=False)
        self.assertEqual((row["device"], row["inode"], row["owner_uid"], row["owner_gid"],
                          row["mode"], row["size_bytes"]),
                         (info.st_dev, info.st_ino, 0, 0, 0o444, len(content)))
        self.assertEqual(_hash_fd(held[0]), expected.sha256)
        self.assertEqual(row["receipt_handle"], "output-receipt")
        self.assertEqual(row["kind"], "regular-file")
        os.close(held[0])

    def test_current_path_replacement_is_detected_even_when_held_fd_survives(self) -> None:
        content = b"held output\n"
        expected = SimpleNamespace(
            mode=0o444, size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        held: list[int] = []
        row = self.registry._write_member(
            self.root_fd, "native-entrypoint-manifest", "manifest.json", content,
            expected, "native-entrypoint-manifest-v1", "output-receipt", held)
        os.unlink("native-entrypoint-manifest/manifest.json", dir_fd=self.root_fd)
        replacement_fd = os.open("native-entrypoint-manifest/manifest.json",
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444,
                                 dir_fd=self.root_fd)
        os.write(replacement_fd, content)
        os.close(replacement_fd)
        witness = SimpleNamespace(_root_fd=self.root_fd,
                                  native_output_member_records=(row,))
        try:
            with self.assertRaises(NativeWorkerRuntimeMaterializationUnavailable):
                self.registry._verify_output_member_paths(witness)
        finally:
            os.close(held[0])

    def test_cleanup_preserves_unrecorded_root_owned_data(self) -> None:
        content = b"owned output\n"
        expected = SimpleNamespace(
            mode=0o444, size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        held: list[int] = []
        row = self.registry._write_member(
            self.root_fd, "native-boundary-overlay", "overlay.py", content,
            expected, "native-boundary-overlay-v1", "output-receipt", held)
        os.close(held[0])
        Path(self.parent / self.leaf / "operator-data").write_bytes(b"preserve me")
        root_info = os.fstat(self.root_fd)
        self.registry._remove_leaf_if_owned(
            self.leaf, root_info, (row,), self.parent_fd)
        self.assertEqual((self.parent / self.leaf / "operator-data").read_bytes(), b"preserve me")
        self.assertTrue((self.parent / self.leaf).is_dir())
        self.assertFalse((self.parent / self.leaf / "native-boundary-overlay" / "overlay.py").exists())

    def test_runtime_parent_child_descriptor_closes_on_post_open_failure(self) -> None:
        self.registry.output_receipts = SimpleNamespace(_cas_root=self.parent / "cas")
        opened: list[int] = []
        original_open = os.open

        def recording_open(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            opened.append(fd)
            return fd

        with mock.patch.object(os, "open", side_effect=recording_open), \
                mock.patch.object(os, "fchmod", side_effect=OSError("injected")):
            with self.assertRaises(NativeWorkerRuntimeMaterializationUnavailable):
                self.registry._open_or_create_runtime_parent()
        self.assertEqual(len(opened), 2)
        for descriptor in opened:
            with self.assertRaises(OSError):
                fcntl.fcntl(descriptor, fcntl.F_GETFD)

    def test_committed_venv_descriptor_hashes_actual_receipt_and_observed_executable(self) -> None:
        runtime_root = self.parent / "pm-runtime"
        generation = runtime_root / ("pm-" + "a" * 32)
        receipts = runtime_root / "receipts"
        runtime_root.mkdir(mode=0o700)
        receipts.mkdir(mode=0o700)
        venv = generation / "venv"
        (venv / "bin").mkdir(parents=True, mode=0o700)
        executable = venv / "bin" / "python"
        executable.write_text(
            "#!/bin/sh\nprintf '%s\\n' '{\"version_info\":[3,14,7],\"implementation\":\"cpython\","
            "\"cache_tag\":\"cpython-314\",\"soabi\":\"cpython-314-x86_64-linux-gnu\","
            "\"machine\":\"x86_64\"}'\n", encoding="utf-8")
        executable.chmod(0o555)
        info = executable.stat()
        from hermes_installer.authority.pm_runtime import _hash
        record = {
            "handle": "h" * 40, "generation": "pm-" + "a" * 32,
            "runtime_relative": "venv/bin/python", "runtime_venv_relative": "venv",
            "runtime_closure_sha256": _tree_sha256(venv),
            "runtime_executable_artifact_id": "observed:pm-committed-venv-python",
            "runtime_executable_sha256": _hash(executable),
            "runtime_device": info.st_dev, "runtime_inode": info.st_ino,
            "runtime_uid": info.st_uid, "runtime_gid": info.st_gid,
            "runtime_mode": stat.S_IMODE(info.st_mode),
            "version_info": [3, 14, 7], "implementation": "cpython",
            "cache_tag": "cpython-314", "soabi": "cpython-314-x86_64-linux-gnu",
            "machine": "x86_64", "source_commit": "7085fbf7753266fc4943c55ac04926186bc90005",
            "pm_sync_outcome": "succeeded",
        }
        raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        (receipts / (record["handle"] + ".json")).write_bytes(raw)
        (receipts / (record["handle"] + ".json")).chmod(0o600)
        selected = SimpleNamespace(
            receipt_handle=record["handle"], python_path=executable,
            runtime_sha256=record["runtime_executable_sha256"],
            device=info.st_dev, inode=info.st_ino, uid=info.st_uid,
            gid=info.st_gid, mode=stat.S_IMODE(info.st_mode),
        )
        self.registry.runtime_receipts = SimpleNamespace(
            runtime_root=runtime_root, _record=lambda _handle: dict(record))
        descriptor = self.registry._committed_venv_identity(SimpleNamespace(selection=selected))
        self.assertEqual(descriptor["pm_receipt_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(descriptor["pm_runtime_receipt_handle"], record["handle"])
        self.assertEqual(descriptor["executable_identity_id"], "observed:pm-committed-venv-python")
        self.assertEqual(descriptor["executable_inode"], info.st_ino)
        self.assertEqual(descriptor["runtime_closure_sha256"], record["runtime_closure_sha256"])
        receipt_path = receipts / (record["handle"] + ".json")
        receipt_path.write_bytes(raw[:-1] + b',"handle":"' + record["handle"].encode("ascii") + b'"}')
        with self.assertRaises(NativeWorkerRuntimeMaterializationUnavailable):
            self.registry._committed_venv_identity(SimpleNamespace(selection=selected))
        receipt_path.write_bytes(raw)
        changed = dict(record)
        changed["runtime_executable_sha256"] = "0" * 64
        self.registry.runtime_receipts._record = lambda _handle: changed
        with self.assertRaises(NativeWorkerRuntimeMaterializationUnavailable):
            self.registry._committed_venv_identity(SimpleNamespace(selection=selected))

    def test_active_verifier_reopens_pm_receipt_and_full_venv_after_prepared_guard_expires(self) -> None:
        from hermes_installer.authority import pm_runtime

        runtime_root = self.parent / "active-pm"
        generation = runtime_root / ("pm-" + "b" * 32)
        receipts = runtime_root / "receipts"
        venv = generation / "venv"
        (venv / "bin").mkdir(parents=True, mode=0o700)
        os.chmod(runtime_root, 0o700)
        os.chmod(generation, 0o700)
        receipts.mkdir(mode=0o700)
        executable = venv / "bin" / "python"
        executable.write_text(
            "#!/bin/sh\nprintf '%s\\n' '{\"version_info\":[3,14,7],"
            "\"implementation\":\"cpython\",\"cache_tag\":\"cpython-314\","
            "\"soabi\":\"cpython-314-x86_64-linux-gnu\",\"machine\":\"x86_64\"}'\n",
            encoding="utf-8")
        executable.chmod(0o555)
        info = executable.stat()
        record = {
            "schema": 1, "handle": "p" * 40, "generation": generation.name,
            "source_commit": pm_runtime.SOURCE_COMMIT,
            "pm_lock_sha256": pm_runtime.LOCK_SHA256,
            "uv_sha256": pm_runtime.UV_SHA256,
            "base_python_artifact_id": pm_runtime.PYTHON_ID,
            "base_python_sha256": pm_runtime.PYTHON_SHA256,
            "pm_sync_outcome": "succeeded",
            "runtime_relative": "venv/bin/python",
            "runtime_venv_relative": "venv",
            "runtime_closure_sha256": _tree_sha256(venv),
            "runtime_executable_artifact_id": "observed:pm-committed-venv-python",
            "runtime_executable_sha256": pm_runtime._hash(executable),
            "runtime_device": info.st_dev, "runtime_inode": info.st_ino,
            "runtime_uid": info.st_uid, "runtime_gid": info.st_gid,
            "runtime_mode": stat.S_IMODE(info.st_mode),
            "version_info": [3, 14, 7], "implementation": "cpython",
            "cache_tag": "cpython-314", "soabi": "cpython-314-x86_64-linux-gnu",
            "machine": "x86_64",
        }
        raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        (receipts / (record["handle"] + ".json")).write_bytes(raw)
        (receipts / (record["handle"] + ".json")).chmod(0o600)
        descriptor = {
            "pm_runtime_receipt_handle": record["handle"],
            "pm_receipt_sha256": hashlib.sha256(raw).hexdigest(),
            "pm_generation": generation.name, "source_commit": record["source_commit"],
            "runtime_relative": record["runtime_relative"],
            "runtime_venv_relative": record["runtime_venv_relative"],
            "runtime_closure_sha256": record["runtime_closure_sha256"],
            "executable_identity_id": "observed:pm-committed-venv-python",
            "executable_sha256": record["runtime_executable_sha256"],
            "executable_device": info.st_dev, "executable_inode": info.st_ino,
            "executable_uid": info.st_uid, "executable_gid": info.st_gid,
            "executable_mode": stat.S_IMODE(info.st_mode),
        }
        self.registry.runtime_receipts = SimpleNamespace(
            runtime_root=runtime_root, _record=lambda _handle: dict(record))
        receipt = SimpleNamespace(pm_runtime_receipt_handle=record["handle"],
                                 committed_venv_identity=descriptor)
        row = {"pm_runtime_receipt_handle": record["handle"],
               "committed_venv_identity": descriptor}
        self.registry._verify_committed_pm_venv(receipt, row)

        executable.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        executable.chmod(0o555)
        with self.assertRaises(NativeWorkerRuntimeMaterializationUnavailable):
            self.registry._verify_committed_pm_venv(receipt, row)


if __name__ == "__main__":
    unittest.main()
