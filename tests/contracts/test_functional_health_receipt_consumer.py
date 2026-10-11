from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import sys
import tempfile
import threading
import unittest

from hermes_installer.authority.functional_health_receipt_consumer import (
    RootFunctionalHealthCompletion,
    RootFunctionalHealthReceiptConsumer,
    _append_health_record_at,
    _read_health_record_at,
    _unique_object,
)
from hermes_installer.authority.types import AuthorityDenied, canonical_bytes


_HEALTH_FIELDS = {
    "schema", "health_receipt_handle", "operation_id", "enrollment_id", "profile_id",
    "process_generation", "bootstrap_transaction_handle", "committed_enrollment_receipt_id",
    "service_generation_digest", "process_id", "loader_ready_event_id", "native_request_event_id",
    "tool_invocation_event_id", "tool_result_event_id", "provider_result_event_id",
    "terminal_receipt_handle", "result_schema_id", "result_sha256", "parent_closure_digest",
    "health_run_proof_sha256", "status", "issued_monotonic", "expires_monotonic",
}


def _completion_bytes(transaction_id: str = "journal-tx-1") -> bytes:
    receipt = {name: "event:1" for name in _HEALTH_FIELDS}
    receipt.update({
        "schema": 2, "health_receipt_handle": "h" * 32,
        "service_generation_digest": "a" * 64, "result_sha256": "b" * 64,
        "parent_closure_digest": "c" * 64, "health_run_proof_sha256": "d" * 64,
        "status": "passed",
        "issued_monotonic": 1.0, "expires_monotonic": 2.0,
        "provider_result_event_id": None,
    })
    row = {
        "schema": 1, "journal_transaction_id": transaction_id,
        "transaction_handle": "bootstrap-tx-1", "enrollment_id": "enrollment-1",
        "profile_id": "profile-1", "process_generation": "process-generation-1",
        "service_generation_digest": "a" * 64, "health_receipt_handle": "h" * 32,
        "health_receipt": receipt, "publication_receipt_handle": "publication-1",
    }
    return canonical_bytes(row)


class FunctionalHealthReceiptConsumerContracts(unittest.TestCase):
    def test_lifecycle_completion_cannot_be_fabricated(self):
        with self.assertRaises(TypeError):
            RootFunctionalHealthCompletion(
                1, "a" * 32, "transaction:1", "enrollment:1", "profile:1",
                "process-generation:1", "b" * 64, "c" * 32, {"status": "passed"},
                "publication:1")

    def test_consumer_requires_one_composed_root_registry_authority_and_observer(self):
        with self.assertRaises(AuthorityDenied):
            RootFunctionalHealthReceiptConsumer.from_root_committed_health(
                object(), object(), object(), object(), object())


@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                     "root-owned journal filesystem primitive proof requires isolated Linux")
class FunctionalHealthJournalFilesystemEffects(unittest.TestCase):
    """Storage primitive effects only; these tests do not issue health authority."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hermes-health-journal-")
        os.chmod(self.temp.name, 0o700)
        self.fd = os.open(self.temp.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def tearDown(self):
        os.close(self.fd)
        self.temp.cleanup()

    def test_atomic_write_replay_preserves_foreign_entry_and_rejects_conflict(self):
        foreign = os.open("foreign.keep", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                          dir_fd=self.fd)
        os.write(foreign, b"keep")
        os.close(foreign)
        encoded = _completion_bytes()
        _append_health_record_at(self.fd, "journal-tx-1", encoded)
        self.assertEqual(_read_health_record_at(self.fd, "journal-tx-1")[1], encoded)
        conflict_row = json.loads(encoded)
        conflict_row["health_receipt_handle"] = "x" * 32
        conflict_row["health_receipt"]["health_receipt_handle"] = "x" * 32
        with self.assertRaises(AuthorityDenied):
            _append_health_record_at(self.fd, "journal-tx-1", canonical_bytes(conflict_row))
        self.assertEqual(sorted(os.listdir(self.fd)), sorted(["foreign.keep", hashlib.sha256(b"journal-tx-1").hexdigest() + ".json"]))
        foreign_fd = os.open("foreign.keep", os.O_RDONLY, dir_fd=self.fd)
        try:
            self.assertEqual(os.read(foreign_fd, 8), b"keep")
        finally:
            os.close(foreign_fd)

    def test_reconciles_crash_after_atomic_link_before_temp_unlink(self):
        transaction_id = "journal-crash"
        encoded = _completion_bytes(transaction_id)
        filename = hashlib.sha256(transaction_id.encode()).hexdigest() + ".json"
        temporary = ".health-" + secrets.token_hex(16) + ".tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=self.fd)
        os.write(fd, encoded)
        os.fsync(fd)
        os.close(fd)
        os.link(temporary, filename, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        self.assertEqual(os.stat(filename, dir_fd=self.fd).st_nlink, 2)
        self.assertEqual(_read_health_record_at(self.fd, transaction_id)[1], encoded)
        self.assertEqual(os.stat(filename, dir_fd=self.fd).st_nlink, 1)
        self.assertNotIn(temporary, os.listdir(self.fd))

    def test_same_transaction_race_has_one_exact_record(self):
        encoded = _completion_bytes("journal-race")
        failures = []

        def append():
            try:
                _append_health_record_at(self.fd, "journal-race", encoded)
            except Exception as exc:  # surfaced after both writers finish
                failures.append(exc)

        workers = [threading.Thread(target=append) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertEqual(failures, [])
        self.assertEqual(_read_health_record_at(self.fd, "journal-race")[1], encoded)
        self.assertEqual([name for name in os.listdir(self.fd) if name.endswith(".json")],
                         [hashlib.sha256(b"journal-race").hexdigest() + ".json"])

    def test_symlink_and_noncanonical_duplicate_records_are_denied_without_following(self):
        tx = "journal-symlink"
        filename = hashlib.sha256(tx.encode()).hexdigest() + ".json"
        os.symlink("foreign.keep", filename, dir_fd=self.fd)
        with self.assertRaises(AuthorityDenied):
            _read_health_record_at(self.fd, tx)
        with self.assertRaises(AuthorityDenied):
            _append_health_record_at(self.fd, tx, _completion_bytes(tx))
        self.assertTrue(stat.S_ISLNK(os.stat(filename, dir_fd=self.fd, follow_symlinks=False).st_mode))
        with self.assertRaises(ValueError):
            json.loads(b'{"a":1,"a":2}', object_pairs_hook=_unique_object)
        with self.assertRaises(AuthorityDenied):
            _append_health_record_at(self.fd, "journal-large", b"x" * (128 * 1024 + 1))


if __name__ == "__main__":
    unittest.main()
