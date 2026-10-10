from __future__ import annotations

import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from hermes_installer.authority.application_runtime_archive import (
    MANIFEST_NAME,
    PYTHON_RUNTIME_ALIASES,
    RuntimeArchiveError,
    extract_verified_runtime_archive,
    inspect_runtime_archive,
    write_runtime_archive,
)


class ApplicationRuntimeArchiveTests(unittest.TestCase):
    def _fixture(self, root: Path) -> None:
        (root / "bin").mkdir()
        executable = root / "bin" / "graphify"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        selected_python = root / "bin" / "python3.14"
        selected_python.write_bytes(b"#!/bin/sh\nselected PM runtime\n")
        selected_python.chmod(0o755)
        (root / "lib").mkdir()
        (root / "lib" / "module.py").write_text("VALUE = 7\n", encoding="utf-8")
        for alias in PYTHON_RUNTIME_ALIASES:
            path = root / alias
            path.parent.mkdir(exist_ok=True)
            path.symlink_to("python3.14")

    def test_write_and_independent_archive_inspection_bind_all_members(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / "env"
            root.mkdir()
            self._fixture(root)
            archive = Path(base) / "environment.tar"
            produced = write_runtime_archive(root, archive, application_id="graphify",
                                             runtime_kind="python", entrypoint="bin/python3.14",
                                             interpreter_aliases=PYTHON_RUNTIME_ALIASES)
            with archive.open("rb") as stream:
                observed = inspect_runtime_archive(stream, expected_application_id="graphify",
                                                   expected_runtime_kind="python",
                                                   expected_entrypoint="bin/python3.14")
            self.assertEqual(produced.archive_sha256, observed.archive_sha256)
            self.assertEqual(produced.manifest_sha256, observed.manifest_sha256)
            self.assertEqual({row.path for row in observed.members},
                             {"bin", "bin/graphify", "bin/python3.14", "lib", "lib/module.py"})

    def test_archive_is_deterministic_and_rejects_metadata_drift(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / "env"
            root.mkdir()
            self._fixture(root)
            first, second = Path(base) / "one.tar", Path(base) / "two.tar"
            kwargs = dict(application_id="graphify", runtime_kind="python",
                          entrypoint="bin/python3.14", interpreter_aliases=PYTHON_RUNTIME_ALIASES)
            write_runtime_archive(root, first, **kwargs)
            write_runtime_archive(root, second, **kwargs)
            self.assertEqual(first.read_bytes(), second.read_bytes())

            changed = io.BytesIO()
            with tarfile.open(first, "r:") as source, tarfile.open(
                    fileobj=changed, mode="w", format=tarfile.PAX_FORMAT) as target:
                for info in source:
                    if info.name == "bin/graphify":
                        info.mode = 0o644
                    body = source.extractfile(info) if info.isfile() else None
                    target.addfile(info, body)
            changed.seek(0)
            with self.assertRaises(RuntimeArchiveError):
                inspect_runtime_archive(changed, expected_application_id="graphify",
                                        expected_runtime_kind="python",
                                        expected_entrypoint="bin/python3.14")

    def test_rejects_symlink_escape_and_wrong_interpreter_alias_selection(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / "env"
            root.mkdir()
            self._fixture(root)
            (root / "lib" / "escape").symlink_to("../../outside")
            with self.assertRaises(RuntimeArchiveError):
                write_runtime_archive(root, Path(base) / "environment.tar",
                                      application_id="graphify", runtime_kind="python",
                                      entrypoint="bin/python3.14",
                                      interpreter_aliases=PYTHON_RUNTIME_ALIASES)

        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / "env"
            root.mkdir()
            self._fixture(root)
            with self.assertRaises(RuntimeArchiveError):
                write_runtime_archive(root, Path(base) / "environment.tar",
                                      application_id="graphify", runtime_kind="python",
                                      entrypoint="bin/python3.14",
                                      interpreter_aliases={"bin/attacker"})

    def test_rejects_archive_path_traversal_before_extraction(self):
        members = [{"path": "../outside", "kind": "file", "mode": 0o644,
                    "size_bytes": 1, "sha256": "0" * 64},
                   {"path": "bin/python3.14", "kind": "file", "mode": 0o755,
                    "size_bytes": 1, "sha256": "0" * 64}]
        manifest = json.dumps({"schema": 1, "application_id": "graphify",
                               "runtime_kind": "python", "entrypoint": "bin/python3.14",
                               "interpreter_aliases": sorted(PYTHON_RUNTIME_ALIASES),
                               "members": members}, sort_keys=True,
                              separators=(",", ":")).encode("ascii")
        body = io.BytesIO()
        with tarfile.open(fileobj=body, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, content, mode in ((MANIFEST_NAME, manifest, 0o444), ("../outside", b"x", 0o644)):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.uid, info.gid, info.mtime = len(content), mode, 0, 0, 0
                archive.addfile(info, io.BytesIO(content))
        body.seek(0)
        with self.assertRaises(RuntimeArchiveError):
            inspect_runtime_archive(body, expected_application_id="graphify",
                                    expected_runtime_kind="python",
                                    expected_entrypoint="bin/python3.14")

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0,
                         "root-owned extraction fixture runs only in isolated root Linux CI")
    def test_root_extract_reopens_content_and_binds_only_held_interpreter_alias(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / "env"
            root.mkdir()
            self._fixture(root)
            interpreter = Path(base) / "python3.14"
            interpreter.write_bytes(b"#!/bin/sh\nselected PM runtime\n")
            interpreter.chmod(0o755)
            archive = Path(base) / "environment.tar"
            expected = write_runtime_archive(root, archive, application_id="graphify",
                                             runtime_kind="python", entrypoint="bin/python3.14",
                                             interpreter_aliases=PYTHON_RUNTIME_ALIASES)
            destination = Path(base) / "runtime"
            with archive.open("rb") as stream:
                actual = extract_verified_runtime_archive(
                    stream, destination, expected_application_id="graphify",
                    expected_runtime_kind="python", expected_entrypoint="bin/python3.14",
                    expected_uid=0, held_interpreter=interpreter)
            self.assertEqual(expected.manifest_sha256, actual.manifest_sha256)
            self.assertEqual((destination / "lib" / "module.py").read_text(), "VALUE = 7\n")
            copied = destination / "bin/python3.14"
            self.assertEqual(copied.read_bytes(), interpreter.read_bytes())
            for alias in PYTHON_RUNTIME_ALIASES:
                self.assertEqual((destination / alias).resolve(strict=True), copied.resolve(strict=True))


if __name__ == "__main__":
    unittest.main()
