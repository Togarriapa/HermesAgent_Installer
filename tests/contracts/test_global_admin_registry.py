"""Effect and concurrency contracts for the fixed original-admin registry."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

from hermes_installer.remote import global_admin


class GlobalAdminRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("the fixed registry contract requires the Pi Root actor")
        self.tmp = tempfile.TemporaryDirectory(prefix="hermes-global-admin-")
        self.directory = Path(self.tmp.name) / "core-runtime"
        self.directory.mkdir(mode=0o700)
        os.chown(self.directory, 0, 0)
        os.chmod(self.directory, 0o700)
        self.paths = (global_admin.GLOBAL_ADMIN_DIRECTORY, global_admin.GLOBAL_ADMIN_PATH,
                      global_admin.GLOBAL_ADMIN_LOCK_PATH)
        global_admin.GLOBAL_ADMIN_DIRECTORY = self.directory
        global_admin.GLOBAL_ADMIN_PATH = self.directory / "global-admin.json"
        global_admin.GLOBAL_ADMIN_LOCK_PATH = self.directory / "global-admin.lock"

    def tearDown(self) -> None:
        (global_admin.GLOBAL_ADMIN_DIRECTORY, global_admin.GLOBAL_ADMIN_PATH,
         global_admin.GLOBAL_ADMIN_LOCK_PATH) = self.paths
        self.tmp.cleanup()

    def enroll(self) -> dict[str, object]:
        return global_admin.enroll(hostname="jarvis.example.test", issuer="https://access.example.test",
            audience="audience-id", email="Owner@Example.Test", subject="immutable-subject",
            expected_sha256=None)

    def test_cas_revocation_and_same_identity_reactivation_increment_revision(self) -> None:
        active = self.enroll()
        self.assertEqual(active["revision"], 1)
        revoked = global_admin.revoke(expected_sha256=str(active["record_sha256"]))
        self.assertEqual(revoked["revision"], 2)
        status = global_admin.current_status()
        self.assertEqual(status["state"], "revoked")
        self.assertEqual(status["record_sha256"], revoked["record_sha256"])
        with self.assertRaises(global_admin.GlobalAdminError):
            global_admin.enroll(hostname="jarvis.example.test", issuer="https://access.example.test",
                audience="audience-id", email="owner@example.test", subject="other-subject",
                expected_sha256=str(revoked["record_sha256"]), reactivate_revision=2,
                reactivate_sha256=str(revoked["record_sha256"]))
        active_again = global_admin.enroll(hostname="jarvis.example.test", issuer="https://access.example.test",
            audience="audience-id", email="owner@example.test", subject="immutable-subject",
            expected_sha256=str(revoked["record_sha256"]), reactivate_revision=2,
            reactivate_sha256=str(revoked["record_sha256"]))
        self.assertEqual(active_again["revision"], 3)
        with self.assertRaises(global_admin.GlobalAdminError):
            global_admin.revoke(expected_sha256=str(revoked["record_sha256"]))

    def test_native_scope_holds_shared_lock_and_rejects_wrong_or_stale_identity(self) -> None:
        active = self.enroll()
        finished = threading.Event()
        result: list[object] = []

        def revoke_after_native_read() -> None:
            result.append(global_admin.revoke(expected_sha256=str(active["record_sha256"])))
            finished.set()

        with global_admin.authorize_native(hostname="jarvis.example.test",
                issuer="https://access.example.test", audience="audience-id",
                email="owner@example.test", subject="immutable-subject",
                expected_revision=1, expected_sha256=str(active["record_sha256"])):
            worker = threading.Thread(target=revoke_after_native_read)
            worker.start()
            time.sleep(0.05)
            self.assertFalse(finished.is_set(), "revocation must wait for the native transaction lock")
        worker.join(timeout=2)
        self.assertTrue(finished.is_set())
        with self.assertRaises(global_admin.GlobalAdminError):
            with global_admin.authorize_native(hostname="jarvis.example.test",
                    issuer="https://access.example.test", audience="audience-id",
                    email="owner@example.test", subject="immutable-subject",
                    expected_revision=1, expected_sha256=str(active["record_sha256"])):
                self.fail("stale pre-revocation preview entered a native operation")
        self.assertEqual(global_admin.current_status()["state"], "revoked")

    def test_record_shape_and_filesystem_custody_fail_closed(self) -> None:
        active = self.enroll()
        raw = global_admin.GLOBAL_ADMIN_PATH.read_bytes()
        row = json.loads(raw)
        row["email"] = "owner@example.test"
        global_admin.GLOBAL_ADMIN_PATH.write_text(json.dumps(row), encoding="ascii")
        os.chmod(global_admin.GLOBAL_ADMIN_PATH, 0o600)
        with self.assertRaises(global_admin.GlobalAdminError):
            global_admin.current_status()
        global_admin.GLOBAL_ADMIN_PATH.unlink()
        global_admin.GLOBAL_ADMIN_PATH.symlink_to("/etc/passwd")
        with self.assertRaises(global_admin.GlobalAdminError):
            global_admin.current_status()
        self.assertNotEqual(active["record_sha256"], "0" * 64)


if __name__ == "__main__":
    unittest.main()
