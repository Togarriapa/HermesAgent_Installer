"""Root-only Linux integration test for the real offline venv/pip executor.

Uses tiny locally built fixture wheels and the same fixed installer executor,
but does not claim the Coral ARM64 runtime, official wheels, or TPU acceptance.
Run with the host-custody Linux job as root; unsupported network namespaces skip.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hermes_installer.artifacts import (
    ResolvedArtifact, _install_coral_package_set, _mkdir_service_directory,
)
from hermes_installer.authority.types import AuthorityDenied


def _wheel(*, distribution: str, module_files: dict[str, bytes], version: str) -> bytes:
    normalized = distribution.replace("-", "_")
    dist_info = f"{normalized}-{version}.dist-info"
    files = {
        **module_files,
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: hermes-fixture\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n"
        ).encode(),
    }
    record_path = f"{dist_info}/RECORD"
    rows = []
    for name, value in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()
        rows.append((name, f"sha256={digest}", str(len(value))))
    rows.append((record_path, "", ""))
    record = io.StringIO()
    csv.writer(record, lineterminator="\n").writerows(rows)
    files[record_path] = record.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    return output.getvalue()


@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                     "requires root on Linux for UID drop and network namespace")
class OfflinePackageSetLinuxTests(unittest.TestCase):
    def test_tiny_local_wheels_install_in_isolated_service_venv(self):
        unshare = Path("/usr/bin/unshare")
        setpriv = Path("/usr/bin/setpriv")
        if not unshare.is_file() or not setpriv.is_file():
            self.skipTest("Linux unshare/setpriv tools are unavailable")
        probe = subprocess.run([str(unshare), "--net", "--", "/usr/bin/true"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=5, check=False)
        if probe.returncode:
            self.skipTest("runner cannot create a private network namespace")

        service_uid = 65534
        service_gid = 65534
        with tempfile.TemporaryDirectory(prefix="hermes-package-set-fixture-", dir="/run") as temp:
            root = Path(temp)
            runtime = root / "python"
            shutil.copy2(sys.executable, runtime)
            runtime.chmod(0o755)
            os.chown(runtime, 0, 0)
            venv_root = root / "service-venvs"
            venv_root.mkdir(mode=0o700)
            os.chown(venv_root, service_uid, service_gid)
            output_root = _mkdir_service_directory(
                venv_root, "custody-check", service_uid, service_gid,
            )
            output_info = output_root.lstat()
            self.assertEqual((output_info.st_uid, output_info.st_gid,
                              output_info.st_mode & 0o777),
                             (service_uid, service_gid, 0o700))
            unsafe = venv_root / "unsafe-root-owned"
            unsafe.mkdir(mode=0o700)
            with self.assertRaises(AuthorityDenied):
                _mkdir_service_directory(venv_root, unsafe.name, service_uid, service_gid)
            shutil.rmtree(unsafe)
            output_root.rmdir()

            wheel_rows = (
                SimpleNamespace(distribution="numpy", version="1.26.4",
                                artifact_id="tiny-numpy", artifact_sha256="",
                                artifact_bytes=0, identity="numpy/numpy"),
                SimpleNamespace(distribution="tflite-runtime", version="2.14.0",
                                artifact_id="tiny-tflite", artifact_sha256="",
                                artifact_bytes=0, identity="tensorflow/tflite-runtime"),
            )
            payloads = (
                _wheel(distribution="numpy", version="1.26.4",
                       module_files={"numpy/__init__.py": b"fixture = True\n"}),
                _wheel(distribution="tflite-runtime", version="2.14.0",
                       module_files={"tflite_runtime/__init__.py": b"",
                                     "tflite_runtime/interpreter.py": b"fixture = True\n"}),
            )
            artifacts = []
            for wheel, content in zip(wheel_rows, payloads, strict=True):
                wheel.artifact_sha256 = hashlib.sha256(content).hexdigest()
                wheel.artifact_bytes = len(content)
                artifact_path = root / f"{wheel.artifact_id}.whl"
                artifact_path.write_bytes(content)
                artifact_path.chmod(0o444)
                os.chown(artifact_path, 0, 0)
                artifacts.append(ResolvedArtifact(
                    artifact_id=wheel.artifact_id, version=wheel.version,
                    path=artifact_path, sha256=wheel.artifact_sha256,
                    size_bytes=wheel.artifact_bytes,
                ))

            spec = SimpleNamespace(
                package_set_id="tiny-fixture-set", manifest_sha256="1" * 64,
                runtime_build_attestation_digest="2" * 64,
                runtime_executable_sha256=hashlib.sha256(runtime.read_bytes()).hexdigest(),
                wheel_entries=wheel_rows,
            )
            binding = SimpleNamespace(
                service_uid=service_uid, service_gid=service_gid,
                runtime_executable=str(runtime), venv_root=str(venv_root),
            )
            expected_names = {
                "numpy/numpy": "numpy-1.26.4-py3-none-any.whl",
                "tensorflow/tflite-runtime": "tflite_runtime-2.14.0-py3-none-any.whl",
            }
            with patch("hermes_installer.artifacts._expected_wheel_filename",
                       side_effect=lambda wheel: expected_names[wheel.identity]):
                destination, digest = _install_coral_package_set(
                spec, binding, tuple(artifacts), 0, 120,
                    time.monotonic() + 120, lambda: False,
                    before_process=lambda: None, before_activation=lambda: None,
                )
            self.assertEqual(destination.owner().pw_uid, service_uid)
            self.assertEqual(len(digest), 64)
            python = destination / "bin/python"
            check = subprocess.run(
                [str(python), "-I", "-c",
                 "import importlib.metadata as m, numpy, tflite_runtime.interpreter; "
                 "assert m.version('numpy')=='1.26.4'; "
                 "assert m.version('tflite-runtime')=='2.14.0'; "
                 "assert numpy.fixture and tflite_runtime.interpreter.fixture"],
                cwd=root, env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1"},
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20, check=False,
            )
            self.assertEqual(check.returncode, 0, check.stdout.decode(errors="replace"))


if __name__ == "__main__":
    unittest.main()
