"""Failure tests for stage-zero installed release custody."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hermes_installer.authority.installer_release import (
    DEPLOYMENT_RECEIPT_PATH, InstalledRootReleaseVerifier, InstallerReleaseError,
    RootActorObservation, VerifiedInstallerReleaseReceipt, _open_verified_fd,
    _read_fixed_file, _safe_relative, _verify_complete_tree, _SEAL,
    _artifact_id_for, _module_name, _validate_fixed_layout_role,
)
from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentPending


class InstalledReleaseVerifierTests(unittest.TestCase):
    def test_dtos_cannot_be_constructed_without_verifier_seal(self):
        with self.assertRaises(TypeError):
            VerifiedInstallerReleaseReceipt(None, release_root=Path("/"), release_commit="0" * 40,
                deployment_receipt_sha256="0" * 64, root_device=0, root_inode=1,
                closure_manifest_relative_path="closure.json", closure_manifest_sha256="0" * 64,
                baseline_tag_object="0" * 40, baseline_commit="0" * 40,
                baseline_tree_sha256="0" * 64, amendment_manifest_sha256="0" * 64,
                files=(), selected_plan_artifact_id="", selected_plan_sha256="0" * 64,
                root_fd=-1, expected_uid=0)
        with self.assertRaises(TypeError):
            RootActorObservation(None, pid=1, uid=0, gid=0, start_time=1,
                launcher=("/x", 1, 1, "0" * 64), interpreter=("/y", 1, 1, "0" * 64),
                module_origins=(), namespace_inodes=(), isolated_import_facts=(), pidfd=-1)

    def test_production_constructor_has_no_caller_path_override(self):
        self.assertEqual(DEPLOYMENT_RECEIPT_PATH, Path("/var/lib/hermes-installer/deployments/current.json"))
        with self.assertRaises(InstallerReleaseError):
            InstalledRootReleaseVerifier._load_deployment_receipt(Path("/tmp/fake.json"), expected_uid=0)
        if not os.sys.platform.startswith("linux"):
            with self.assertRaises(BootstrapEnrollmentPending):
                InstalledRootReleaseVerifier.from_current_root_process()

    @unittest.skipUnless(os.sys.platform.startswith("linux") and hasattr(os, "pidfd_open"),
                         "requires Linux PIDFD")
    def test_actor_rejects_stale_process_starttime(self):
        pidfd = os.pidfd_open(os.getpid(), 0)
        actor = RootActorObservation(_SEAL, pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
            start_time=1, launcher=("/missing", 0, 0, "0" * 64),
            interpreter=("/missing", 0, 0, "0" * 64), module_origins=(),
            namespace_inodes=(), isolated_import_facts=(), pidfd=pidfd)
        class LiveRelease:
            def verify_current(self):
                return None
        try:
            with self.assertRaises(InstallerReleaseError):
                actor.verify_current(LiveRelease())
        finally:
            actor.close()

    def test_relative_paths_reject_traversal_and_platform_separators(self):
        for path in ("../etc/passwd", "a/../../x", "a\\b", "/absolute", "", "a//b"):
            self.assertFalse(_safe_relative(path), path)
        self.assertTrue(_safe_relative("plans/bootstrap-policy.json"))

    def test_installed_release_roles_use_exact_paths_and_module_ids(self):
        self.assertEqual(_module_name("lib/python/hermes_installer/authority/daemon.py"),
                         "hermes_installer.authority.daemon")
        self.assertEqual(_module_name("lib/python/hermes_installer/__init__.py"),
                         "hermes_installer")
        for malformed in (
            "src/hermes_installer/authority/daemon.py",
            "lib/python/a..b.py",
            "lib/python/trailing..py",
            "lib/python/__init__.py",
            "lib/python/a/b.pyc",
        ):
            with self.subTest(path=malformed), self.assertRaises(InstallerReleaseError):
                _module_name(malformed)
        self.assertEqual(_artifact_id_for("lib/python/hermes_installer/authority/daemon.py", ["module"]),
                         "installer-module:hermes_installer.authority.daemon")
        _validate_fixed_layout_role("runtime/bin/python", "1" * 64, 10, ["interpreter"])
        _validate_fixed_layout_role("runtime/bin/python3", "1" * 64, 10, ["runtime-member"])
        _validate_fixed_layout_role("runtime/lib/python3.14/os.py", "1" * 64, 10, ["runtime-member"])
        with self.assertRaises(InstallerReleaseError):
            _validate_fixed_layout_role("runtime/bin/python3", "1" * 64, 10, ["interpreter"])
        for path, roles in (
            ("runtime/bin/python", ["runtime-member"]),
            ("runtime/bin/python3", ["interpreter", "runtime-member"]),
            ("lib/python/example.py", ["runtime-member"]),
            ("runtime/lib/example.so", ["module"]),
        ):
            with self.subTest(path=path, roles=roles), self.assertRaises(InstallerReleaseError):
                _validate_fixed_layout_role(path, "1" * 64, 10, roles)
        with self.assertRaises(InstallerReleaseError):
            _validate_fixed_layout_role("runtime/lib/example.so", "1" * 64, 10, ["runtime-member"], mode=0o755)
        with self.assertRaises(InstallerReleaseError):
            _validate_fixed_layout_role("templates/bootstrap-compiler-template-v1.json",
                                        "0" * 64, 4281, ["template"])
        with self.assertRaises(InstallerReleaseError):
            _validate_fixed_layout_role("plans/bootstrap-policy-v1.json",
                                        "1" * 64, 10, ["bootstrap-policy"])

    def test_current_fixed_template_closure_matches_v72_v77_v81_pins(self):
        from hermes_installer.authority.installer_release import FIXED_TEMPLATES
        expected = {
            "templates/root-setup-plan-template-v1.json":
                ("installer-root-setup-plan-template-v1",
                 "210114d336b54ec86b40861a1d808508db48d20c9ecfb0a20b30049b2e4f84f5", 920),
            "templates/bootstrap-receipt-bindings-template-v1.json":
                ("installer-bootstrap-receipt-bindings-template-v1",
                 "2036e9443b8c1c085cf7c90a4eb26c162f7d787f030cd759e35d92ca17b3e609", 10195),
            "templates/composio-whatsapp-catalog-read-policy-v1.json":
                ("installer-composio-whatsapp-catalog-read-policy-v1",
                 "319076116a060e371c10886e5c2cfea274ed4d985aa03f5e66a4f611f949cfc5", 528),
        }
        actual = {path: (artifact_id, digest, size)
                  for artifact_id, path, digest, size in FIXED_TEMPLATES}
        for path, value in expected.items():
            self.assertEqual(actual[path], value)
        self.assertEqual(len(actual), 6)
        with self.assertRaises(InstallerReleaseError):
            _validate_fixed_layout_role(
                "templates/composio-whatsapp-catalog-read-policy-v1.json",
                "0" * 64, 528, ["template"],
            )

    def test_open_verified_file_checks_digest_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "good").write_bytes(b"approved")
            os.chmod(root / "good", 0o444)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                expected = hashlib.sha256(b"approved").hexdigest()
                fd = _open_verified_fd(root_fd, "good", expected,
                                       expected_uid=os.getuid(), expected_size=8)
                try:
                    self.assertEqual(os.read(fd, 8), b"approved")
                finally:
                    os.close(fd)
                with self.assertRaises(InstallerReleaseError):
                    _open_verified_fd(root_fd, "good", "0" * 64, expected_uid=os.getuid())
                (root / "link").symlink_to(root / "good")
                with self.assertRaises(InstallerReleaseError):
                    _open_verified_fd(root_fd, "link", expected, expected_uid=os.getuid())
            finally:
                os.close(root_fd)

    def test_receipt_requires_exact_keys_candidate_path_and_baseline(self):
        receipt = {
            "schema": 1, "receipt_id": "installer-release:" + "a" * 40,
            "candidate_git_sha": "a" * 40,
            "release_root": "/usr/lib/hermes-installer/releases/" + "a" * 40,
            "release_device": 1, "release_inode": 2,
            "closure_manifest_relative_path": "release-closure.json",
            "closure_manifest_sha256": "1" * 64, "baseline_tree_sha256": "2" * 64,
            "published_monotonic": 10.0,
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "receipt.json"
            with patch("hermes_installer.authority.installer_release._read_fixed_file",
                       return_value=(json.dumps(receipt).encode(), os.statvfs(td))):
                parsed = InstalledRootReleaseVerifier._load_deployment_receipt(DEPLOYMENT_RECEIPT_PATH,
                                                                                 expected_uid=os.getuid())
            self.assertEqual(parsed["candidate_git_sha"], "a" * 40)
            receipt["release_root"] = "/tmp/attacker"
            with patch("hermes_installer.authority.installer_release._read_fixed_file",
                       return_value=(json.dumps(receipt).encode(), os.statvfs(td))):
                with self.assertRaises(InstallerReleaseError):
                    InstalledRootReleaseVerifier._load_deployment_receipt(DEPLOYMENT_RECEIPT_PATH,
                                                                             expected_uid=os.getuid())
            receipt["release_root"] = "/usr/lib/hermes-installer/releases/" + "a" * 40
            receipt["unexpected"] = True
            with patch("hermes_installer.authority.installer_release._read_fixed_file",
                       return_value=(json.dumps(receipt).encode(), os.statvfs(td))):
                with self.assertRaises(InstallerReleaseError):
                    InstalledRootReleaseVerifier._load_deployment_receipt(DEPLOYMENT_RECEIPT_PATH,
                                                                             expected_uid=os.getuid())

    def test_complete_tree_rejects_unlisted_and_symlink_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "sub").mkdir()
            (root / "sub" / "listed").write_bytes(b"listed")
            (root / "closure.json").write_bytes(b"manifest")
            os.chmod(root / "sub" / "listed", 0o444)
            os.chmod(root / "closure.json", 0o444)
            os.chmod(root / "sub", 0o555)
            os.chmod(root, 0o555)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                _verify_complete_tree(root_fd, {"sub/listed"}, "closure.json", os.getuid())
                os.chmod(root, 0o755)
                (root / "extra").write_bytes(b"unlisted")
                os.chmod(root / "extra", 0o444)
                os.chmod(root, 0o555)
                with self.assertRaises(InstallerReleaseError):
                    _verify_complete_tree(root_fd, {"sub/listed"}, "closure.json", os.getuid())
                os.chmod(root, 0o755)
                (root / "extra").unlink()
                (root / "bad-link").symlink_to(root / "closure.json")
                os.chmod(root, 0o555)
                with self.assertRaises(InstallerReleaseError):
                    _verify_complete_tree(root_fd, {"sub/listed"}, "closure.json", os.getuid())
            finally:
                os.close(root_fd)

    def test_receipt_reader_rejects_writable_or_oversized_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "receipt"
            path.write_bytes(b"x")
            os.chmod(path, 0o666)
            with patch("hermes_installer.authority.installer_release._verify_parents"):
                with self.assertRaises(InstallerReleaseError):
                    _read_fixed_file(DEPLOYMENT_RECEIPT_PATH, 8, os.getuid(), required_mode=0o600)


if __name__ == "__main__":
    unittest.main()
