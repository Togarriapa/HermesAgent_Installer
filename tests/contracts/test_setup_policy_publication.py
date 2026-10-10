"""Filesystem effect and conflict tests for root policy publication helpers."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending
from hermes_installer.authority.setup_policy_publication import (
    _FileSpec, _atomic_replace, _ensure_generation, _read_fixed,
    _receipt_from_record, _verify_active_receipt_descriptor, _restore_compiled_selection,
    _canonical, _sha, POLICY_GENERATIONS,
)


class PolicyPublicationFilesystemTests(unittest.TestCase):
    def test_generation_install_is_immutable_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "generations"
            parent.mkdir(mode=0o700)
            generation = parent / ("a" * 64)
            files = (
                _FileSpec("plans/bootstrap-policy-v1.json", b"{}"),
                _FileSpec("catalog/artifacts.json", b"{}"),
                _FileSpec("publication.json", b"{}"),
            )
            _ensure_generation(parent, generation, "a" * 64, b"{}", files, os.getuid())
            before = os.stat(generation, follow_symlinks=False)
            _ensure_generation(parent, generation, "a" * 64, b"{}", files, os.getuid())
            after = os.stat(generation, follow_symlinks=False)
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            self.assertEqual(before.st_mode & 0o777, 0o555)
            self.assertEqual((generation / "plans/bootstrap-policy-v1.json").read_bytes(), b"{}")

    def test_generation_collision_with_foreign_or_extra_content_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "generations"
            parent.mkdir(mode=0o700)
            generation = parent / ("b" * 64)
            generation.mkdir(mode=0o700)
            marker = generation / "foreign"
            marker.write_bytes(b"preserve")
            os.chmod(marker, 0o444)
            os.chmod(generation, 0o555)
            with self.assertRaises(BootstrapEnrollmentError):
                _ensure_generation(parent, generation, "b" * 64, b"{}", (), os.getuid())
            self.assertEqual(marker.read_bytes(), b"preserve")

    def test_selection_replace_is_cas_and_rejects_inode_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "selection.json"
            path.write_bytes(b"old")
            os.chmod(path, 0o600)
            info = os.stat(path)
            _atomic_replace(path, b"new", os.getuid(), 0o600, (info.st_dev, info.st_ino))
            self.assertEqual(_read_fixed(path, os.getuid(), 0o600, 100)[0], b"new")
            with self.assertRaises(BootstrapEnrollmentPending):
                _atomic_replace(path, b"stale", os.getuid(), 0o600, (info.st_dev, info.st_ino))
            self.assertEqual(path.read_bytes(), b"new")

    def test_selection_replace_rejects_symlink_and_does_not_touch_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_bytes(b"keep")
            os.chmod(target, 0o600)
            path = root / "selection.json"
            path.symlink_to(target)
            with self.assertRaises(BootstrapEnrollmentPending):
                _atomic_replace(path, b"replacement", os.getuid(), 0o600, (1, 1))
            self.assertEqual(target.read_bytes(), b"keep")
            self.assertTrue(path.is_symlink())

    def test_failed_atomic_replace_preserves_previous_selection_and_cleans_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "selection.json"
            path.write_bytes(b"before")
            os.chmod(path, 0o600)
            info = os.stat(path)
            with patch("hermes_installer.authority.setup_policy_publication.os.replace",
                       side_effect=OSError("injected rename failure")):
                with self.assertRaises(OSError):
                    _atomic_replace(path, b"after", os.getuid(), 0o600,
                                    (info.st_dev, info.st_ino))
            self.assertEqual(path.read_bytes(), b"before")
            self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["selection.json"])

    def _active_record(self):
        digest = "a" * 64
        return {
            "schema": 1, "transaction_handle": "t" * 64,
            "publication_sha256": digest, "publication_receipt_handle": "r" * 64,
            "generation_id": "installer-bootstrap-policy-generation-v1",
            "generation_root": str(POLICY_GENERATIONS / digest),
            "generation_device": 1, "generation_inode": 2,
            "policy_sha256": "b" * 64, "artifact_catalog_sha256": "c" * 64,
            "selection_sha256": "d" * 64, "descriptor_sha256": "e" * 64,
            "previous_selection_catalog_sha256": "f" * 64,
            "current_selection_catalog_sha256": "0" * 64,
            "input_receipt_handles": ["i" * 64], "state": "active-committed",
            "updated_monotonic": 10.0, "publication_handle": "p" * 64,
            "claim_digest": "1" * 64, "prepared_generation_id": "prepared-v1",
            "service_generation_digest": "2" * 64,
            "runtime_receipt_handles": ["3" * 64],
            "materialization_receipt_handles": ["4" * 64],
        }

    def test_active_receipt_binds_claim_generation_and_native_receipts(self):
        receipt = _receipt_from_record(self._active_record())
        descriptor = {
            "policy_sha256": receipt.policy_sha256,
            "artifact_catalog_sha256": receipt.artifact_catalog_sha256,
            "selection_sha256": receipt.selection_sha256,
            "inputs": {
                "publication_handle": receipt.publication_handle,
                "claim_digest": receipt.claim_digest,
                "prepared_generation_id": receipt.prepared_generation_id,
                "expected_service_generation_digest": receipt.service_generation_digest,
                "transaction_handle": receipt.transaction_handle,
                "runtime_receipt_handles": list(receipt.runtime_receipt_handles),
                "materialization_receipt_handles": list(receipt.materialization_receipt_handles),
            },
        }
        _verify_active_receipt_descriptor(receipt, descriptor)
        descriptor["inputs"]["claim_digest"] = "9" * 64
        with self.assertRaises(BootstrapEnrollmentError):
            _verify_active_receipt_descriptor(receipt, descriptor)

    def test_active_receipt_rejects_empty_native_receipt_closure(self):
        record = self._active_record()
        record["materialization_receipt_handles"] = []
        with self.assertRaises(BootstrapEnrollmentError):
            _receipt_from_record(record)

    def test_current_selection_reconstructs_exact_compiler_catalog_document(self):
        compiled = {
            "schema": 1, "selection_id": "selected",
            "bootstrap_policies": [{"artifact_id": "installer-bootstrap-policy-v1",
                                    "relative_path": "plans/bootstrap-policy-v1.json",
                                    "sha256": "a" * 64}],
        }
        compiled["catalog_sha256"] = _sha(_canonical(compiled))
        final = dict(compiled)
        final.pop("catalog_sha256")
        final["catalog_sha256"] = "b" * 64
        final["policy_generation"] = {"id": "installer-bootstrap-policy-generation-v1"}
        final_unsigned = {key: value for key, value in final.items() if key != "catalog_sha256"}
        final["catalog_sha256"] = _sha(_canonical(final_unsigned))
        descriptor = {"selection_sha256": _sha(_canonical(compiled)),
                      "inputs": {"selection_catalog_sha256": compiled["catalog_sha256"]}}
        self.assertEqual(_restore_compiled_selection(descriptor, final), compiled)
        final["bootstrap_policies"][0]["sha256"] = "c" * 64
        with self.assertRaises(BootstrapEnrollmentError):
            _restore_compiled_selection(descriptor, final)


if __name__ == "__main__":
    unittest.main()
