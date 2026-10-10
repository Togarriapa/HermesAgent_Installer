from __future__ import annotations

import hashlib
import os
import tempfile
import zipfile
from pathlib import Path
from unittest import TestCase, mock

from hermes_installer.authority import application_environment_builder as builder
from hermes_installer.authority.application_runtime_archive import inspect_runtime_archive


class ApplicationEnvironmentBuilderTests(TestCase):
    def test_export_projection_keeps_only_selected_exact_hash_pins(self):
        exported = b"""--index-url https://pypi.org/simple
aiofiles==25.1.0 \\
    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\
    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
rpds-py==2026.9.1 --hash=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
"""
        rows = builder._parse_export(exported)
        pins = [
            {"name": "aiofiles", "version": "25.1.0", "filename": "aiofiles-25.1.0-py3-none-any.whl",
             "sha256": "b" * 64, "size_bytes": 1},
            {"name": "rpds-py", "version": "2026.9.1", "filename": "rpds_py-2026.9.1-cp314-cp314-manylinux_aarch64.whl",
             "sha256": "c" * 64, "size_bytes": 1},
        ]
        result = builder._requirements_bytes(pins, rows)
        self.assertEqual(result, (
            b"aiofiles==25.1.0 --hash=sha256:" + b"b" * 64 + b"\n"
            b"rpds-py==2026.9.1 --hash=sha256:" + b"c" * 64 + b"\n"))

    def test_export_rejects_unhashed_direct_and_conflicting_rows(self):
        with self.assertRaises(builder.BuildDenied):
            builder._parse_export(b"thing @ https://example.invalid/thing.whl\n")
        with self.assertRaises(builder.BuildDenied):
            builder._parse_export(b"thing==1.0\n")
        with self.assertRaises(builder.BuildDenied):
            builder._parse_export(
                b"thing==1.0 --hash=sha256:" + b"a" * 64 + b"\n"
                b"thing==2.0 --hash=sha256:" + b"b" * 64 + b"\n")

    def test_export_projection_rejects_an_unselected_active_package(self):
        selected = [{"name": "one", "version": "1.0", "filename": "one-1.0-py3-none-any.whl",
                     "sha256": "a" * 64, "size_bytes": 1}]
        rows = builder._parse_export(
            b"one==1.0 --hash=sha256:" + b"a" * 64 + b"\n"
            b"two==2.0 --hash=sha256:" + b"b" * 64 + b"\n")
        with self.assertRaises(builder.BuildDenied):
            builder._requirements_bytes(selected, rows)

    def test_pm_runtime_tree_digest_matches_current_immutable_member_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            (root / "lib").mkdir(parents=True)
            executable = root / "bin-python"
            executable.write_bytes(b"interpreter")
            executable.chmod(0o555)
            (root / "lib" / "module.py").write_bytes(b"MODULE = True\n")
            (root / "lib" / "module.py").chmod(0o444)
            root.chmod(0o555)
            (root / "lib").chmod(0o555)
            measured = builder._runtime_closure_sha256(root, expected_uid=os.getuid())
            self.assertRegex(measured, r"^[0-9a-f]{64}$")
            self.assertEqual(measured,
                             builder._runtime_closure_sha256(root, expected_uid=os.getuid()))
            (root / "lib" / "module.py").chmod(0o664)
            with self.assertRaises(builder.BuildDenied):
                builder._runtime_closure_sha256(root, expected_uid=os.getuid())

    def test_selected_wheelhouse_rechecks_exact_names_bytes_and_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "wheels"
            root.mkdir()
            wheel = root / "demo_pkg-1.2.3-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("demo_pkg-1.2.3.dist-info/METADATA",
                                 "Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.2.3\n\n")
                archive.writestr("demo_pkg/__init__.py", "VALUE = 1\n")
            payload = wheel.read_bytes()
            row = {"name": "demo-pkg", "version": "1.2.3", "filename": wheel.name,
                   "sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload)}
            builder._verify_wheelhouse(root, [row], expected_uid=os.getuid())
            wheel.write_bytes(payload + b"tamper")
            with self.assertRaises(builder.BuildDenied):
                builder._verify_wheelhouse(root, [row], expected_uid=os.getuid())

    def test_project_wheel_must_match_source_distribution_and_exact_console_scripts(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "graphifyy-0.9.82-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("graphifyy-0.9.82.dist-info/METADATA",
                                 "Metadata-Version: 2.1\nName: graphifyy\nVersion: 0.9.82\n\n")
                archive.writestr("graphifyy-0.9.82.dist-info/entry_points.txt",
                                 "[console_scripts]\ngraphify = graphify.__main__:main\n"
                                 "graphify-mcp = graphify.serve:_main\n")
            digest, size = builder._inspect_project_wheel(
                wheel, "graphifyy", "0.9.82", builder.PYTHON_APPS["graphify"][3])
            self.assertEqual((digest, size), (hashlib.sha256(wheel.read_bytes()).hexdigest(),
                                               wheel.stat().st_size))
            with self.assertRaises(builder.BuildDenied):
                builder._inspect_project_wheel(
                    wheel, "graphifyy", "0.9.82", {"graphify": "attacker:main"})
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("graphifyy-0.9.82.dist-info/METADATA",
                                 "Metadata-Version: 2.1\nName: graphifyy\nVersion: 0.9.82\n\n")
                archive.writestr("graphifyy-0.9.82.dist-info/entry_points.txt",
                                 "[console_scripts]\ngraphify = graphify.__main__:main\n"
                                 "[malicious.plugins]\nload = surprise:run\n")
            with self.assertRaises(builder.BuildDenied):
                builder._inspect_project_wheel(
                    wheel, "graphifyy", "0.9.82", builder.PYTHON_APPS["graphify"][3])

    def test_archive_is_deterministic_and_omits_only_the_fixed_runtime_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            env = base / "env"
            (env / "bin").mkdir(parents=True)
            script = env / "bin" / "selected-app"
            script.write_bytes(b"#!/usr/bin/env python3\n")
            script.chmod(0o755)
            interpreter = env / "bin" / "python3.14"
            interpreter.write_bytes(b"selected PM interpreter\n")
            interpreter.chmod(0o755)
            (env / "lib").mkdir()
            (env / "lib" / "module.py").write_bytes(b"VALUE = 3\n")
            for alias in builder.ALIASES:
                target = env / alias
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to("../../held/python3.14")
            first, second = base / "one.tar", base / "two.tar"
            facts1 = builder._write_archive(env, first, "graphify", "bin/python3.14")
            facts2 = builder._write_archive(env, second, "graphify", "bin/python3.14")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(facts1, facts2)
            with first.open("rb") as stream:
                inspected = inspect_runtime_archive(stream, expected_application_id="graphify",
                                                    expected_runtime_kind="python",
                                                    expected_entrypoint="bin/python3.14")
            self.assertEqual({member.path for member in inspected.members},
                             {"bin", "bin/selected-app", "bin/python3.14", "lib", "lib/module.py"})

    def test_archive_denies_unselected_symlink_and_non_executable_entrypoint(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            env = base / "env"
            (env / "bin").mkdir(parents=True)
            (env / "bin" / "entry").write_text("data")
            with self.assertRaises(builder.BuildDenied):
                builder._write_archive(env, base / "bad.tar", "graphify", "bin/entry")
            (env / "bin" / "entry").chmod(0o755)
            (env / "lib").mkdir()
            (env / "lib" / "escape").symlink_to("../../outside")
            with self.assertRaises(builder.BuildDenied):
                builder._write_archive(env, base / "bad.tar", "graphify", "bin/entry")

    def test_archive_uses_regular_pm_interpreter_for_scrapegraph_without_inventing_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            env = base / "env"
            (env / "bin").mkdir(parents=True)
            interpreter = env / "bin" / "python3.14"
            interpreter.write_bytes(b"selected-pm-python-bytes")
            interpreter.chmod(0o755)
            archive_path = base / "runtime.tar"
            builder._write_archive(env, archive_path, "scrapegraph-ai", "bin/python3.14")
            with archive_path.open("rb") as stream:
                inspected = inspect_runtime_archive(
                    stream, expected_application_id="scrapegraph-ai",
                    expected_runtime_kind="python", expected_entrypoint="bin/python3.14")
            self.assertEqual(builder.PYTHON_APPS["scrapegraph-ai"][3], {})
            self.assertEqual(
                {member.path for member in inspected.members}, {"bin", "bin/python3.14"})

    def test_fixed_uv_process_runner_bounds_output_and_requires_success(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "uv"
            executable.write_text("#!/bin/sh\nprintf ok\n")
            executable.chmod(0o700)
            with mock.patch.object(builder, "UV", executable):
                self.assertEqual(builder._run([str(executable), "lock"], cwd=Path(directory), env={}), b"ok")
                executable.write_text("#!/bin/sh\nprintf failure >&2\nexit 7\n")
                executable.chmod(0o700)
                with self.assertRaises(builder.BuildDenied):
                    builder._run([str(executable), "lock"], cwd=Path(directory), env={})
                executable.write_text("#!/bin/sh\nhead -c 1048577 /dev/zero\n")
                executable.chmod(0o700)
                with self.assertRaises(builder.BuildDenied):
                    builder._run([str(executable), "lock"], cwd=Path(directory), env={})

    def test_fixed_route_keeps_hyperframes_out_of_python_builder(self):
        with self.assertRaises(KeyError):
            _ = builder.PYTHON_APPS["hyperframes"]
