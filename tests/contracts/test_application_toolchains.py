from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from hermes_installer.authority.application_toolchains import (
    ApplicationToolchainDenied,
    TOOLCHAINS,
    _extract_archive,
    _fixed_probe,
    _verify_private_tree,
)


def _tar(entries: list[tuple[str, bytes, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:xz") as archive:
        for name, body, mode in entries:
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(body), mode
            archive.addfile(info, io.BytesIO(body))
    return output.getvalue()


class ApplicationToolchainContractTests(unittest.TestCase):
    def test_catalog_has_only_the_exact_reviewed_node_and_bun_pins(self):
        self.assertEqual(set(TOOLCHAINS), {
            "application-node-26.7.0-linux-arm64",
            "application-bun-1.4.3-linux-arm64",
        })
        for row in TOOLCHAINS.values():
            self.assertEqual(row.platform, "linux-arm64")
            self.assertEqual(len(row.sha256), 64)
            self.assertEqual(row.url.split(":", 1)[0], "https")
        node = TOOLCHAINS["application-node-26.7.0-linux-arm64"]
        self.assertEqual((node.version, node.size_bytes, node.sha256), (
            "26.7.0", 32_581_212,
            "afc7a004018485092ac8985b817b0d5684472bd9472e0b57d2ab88737e50090d"))
        bun = TOOLCHAINS["application-bun-1.4.3-linux-arm64"]
        self.assertEqual((bun.version, bun.size_bytes, bun.sha256), (
            "1.4.3", 41_786_424,
            "efa9813da5ed72423bf847f916e8d2c47c0d776add972354026a75e10da9aa21"))
        self.assertEqual(bun.license_sha256,
                         "056696884250b0d682365260cf1487a6501b1665a343ec60e23a1e647043c572")

    def test_source_producer_requires_the_selected_plan_observer_contract(self):
        from hermes_installer.authority.application_toolchain_sources import (
            RootSelectedApplicationToolchainSourceObserver,
        )
        self.assertTrue(callable(
            RootSelectedApplicationToolchainSourceObserver.observe_selected_toolchain_source))
        self.assertTrue(callable(RootSelectedApplicationToolchainSourceObserver.verify_current))
        self.assertTrue(callable(RootSelectedApplicationToolchainSourceObserver.open_blob))

    def test_node_materialization_rejects_traversal_and_duplicate_members(self):
        pin = TOOLCHAINS["application-node-26.7.0-linux-arm64"]
        prefix = "node-v26.7.0-linux-arm64/"
        for entries in (
            [(prefix + "bin/node", b"x", 0o755), (prefix + "../../escape", b"x", 0o644)],
            [(prefix + "bin/node", b"x", 0o755), (prefix + "bin/node", b"y", 0o755)],
        ):
            with self.subTest(entries=entries), TemporaryDirectory() as temp:
                archive_path, destination = Path(temp) / "source.tar.xz", Path(temp) / "tree"
                archive_path.write_bytes(_tar(entries))
                fd = os.open(archive_path, os.O_RDONLY)
                try:
                    with self.assertRaises(ApplicationToolchainDenied):
                        _extract_archive(pin, fd, destination, expected_uid=os.getuid())
                finally:
                    os.close(fd)

    def test_node_materialization_preserves_only_the_exact_runtime_entrypoint(self):
        pin = TOOLCHAINS["application-node-26.7.0-linux-arm64"]
        prefix = "node-v26.7.0-linux-arm64/"
        with TemporaryDirectory() as temp:
            archive_path, destination = Path(temp) / "source.tar.xz", Path(temp) / "tree"
            archive_path.write_bytes(_tar([
                (prefix + "bin/node", b"node-bytes", 0o755),
                (prefix + "bin/npm", b"npm-script", 0o755),
                (prefix + "LICENSE", b"license", 0o644),
            ]))
            fd = os.open(archive_path, os.O_RDONLY)
            try:
                members = _extract_archive(pin, fd, destination, expected_uid=os.getuid())
            finally:
                os.close(fd)
            self.assertEqual(stat.S_IMODE((destination / "bin/node").stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((destination / "bin/npm").stat().st_mode), 0o444)
            self.assertEqual(members["bin/node"]["sha256"], hashlib.sha256(b"node-bytes").hexdigest())
            _verify_private_tree(destination, expected_uid=os.getuid(), expected_members=members)

    def test_bun_materialization_keeps_only_bun_executable(self):
        pin = TOOLCHAINS["application-bun-1.4.3-linux-arm64"]
        with TemporaryDirectory() as temp:
            archive_path, destination = Path(temp) / "source.zip", Path(temp) / "tree"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name, body, mode in (
                    ("bun-linux-aarch64/bun", b"bun-bytes", 0o100755),
                    ("bun-linux-aarch64/install.sh", b"installer", 0o100755),
                ):
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = mode << 16
                    archive.writestr(info, body)
            fd = os.open(archive_path, os.O_RDONLY)
            try:
                members = _extract_archive(pin, fd, destination, expected_uid=os.getuid())
            finally:
                os.close(fd)
            self.assertEqual(stat.S_IMODE((destination / "bun-linux-aarch64/bun").stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((destination / "bun-linux-aarch64/install.sh").stat().st_mode), 0o444)
            _verify_private_tree(destination, expected_uid=os.getuid(), expected_members=members)

    def test_bun_materialization_rejects_traversal_and_duplicate_zip_entries(self):
        pin = TOOLCHAINS["application-bun-1.4.3-linux-arm64"]
        for names in (
            [("bun-linux-aarch64/bun", b"x"), ("../escape", b"x")],
            [("bun-linux-aarch64/bun", b"x"), ("bun-linux-aarch64/bun", b"y")],
        ):
            with self.subTest(names=names), TemporaryDirectory() as temp:
                archive_path, destination = Path(temp) / "source.zip", Path(temp) / "tree"
                with zipfile.ZipFile(archive_path, "w") as archive:
                    for name, body in names:
                        archive.writestr(name, body)
                fd = os.open(archive_path, os.O_RDONLY)
                try:
                    with self.assertRaises(ApplicationToolchainDenied):
                        _extract_archive(pin, fd, destination, expected_uid=os.getuid())
                finally:
                    os.close(fd)

    def test_host_probe_fails_closed_without_linux_arm64_root_fixture(self):
        pin = TOOLCHAINS["application-node-26.7.0-linux-arm64"]
        with TemporaryDirectory() as temp:
            path = Path(temp) / "node"
            path.write_bytes(b"not an executable")
            path.chmod(0o555)
            import os
            fd = os.open(path, os.O_RDONLY)
            try:
                with self.assertRaises(ApplicationToolchainDenied):
                    _fixed_probe(pin, fd, Path(temp), expected_uid=os.geteuid())
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
