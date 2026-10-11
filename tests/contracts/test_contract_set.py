from __future__ import annotations

import hashlib
import json
import unittest

from hermes_installer.authority.contract_set import ContractSetError, verify_contract_set


class ContractSetTests(unittest.TestCase):
    @staticmethod
    def _manifest(files: list[tuple[str, bytes]]) -> bytes:
        rows = [
            {"path": path, "sha256": hashlib.sha256(payload).hexdigest(),
             "size_bytes": len(payload)}
            for path, payload in sorted(files)
        ]
        return json.dumps({"schema": 1, "files": rows}, separators=(",", ":")).encode()

    def test_exact_stable_contract_paths_are_bound_by_manifest_and_payload_digests(self):
        files = [
            ("contracts/schemas/result.json", b'{"type":"object"}'),
            ("contracts/templates/setup.json", b'{"schema":1}'),
        ]
        raw = self._manifest(files)
        available = {
            path: (hashlib.sha256(payload).hexdigest(), len(payload))
            for path, payload in files
        }

        manifest_digest, payload_digest = verify_contract_set(raw, available)

        self.assertEqual(manifest_digest, hashlib.sha256(raw).hexdigest())
        self.assertRegex(payload_digest, r"^[0-9a-f]{64}$")

    def test_missing_extra_and_changed_payloads_are_rejected(self):
        files = [("contracts/schemas/result.json", b"schema")]
        raw = self._manifest(files)
        digest = hashlib.sha256(b"schema").hexdigest()

        for available in (
            {},
            {"contracts/schemas/result.json": (digest, 6),
             "contracts/unlisted.json": ("0" * 64, 1)},
            {"contracts/schemas/result.json": ("0" * 64, 6)},
        ):
            with self.subTest(available=available), self.assertRaises(ContractSetError):
                verify_contract_set(raw, available)

    def test_duplicate_keys_unsorted_rows_and_path_traversal_are_rejected(self):
        duplicate_key = b'{"schema":1,"schema":1,"files":[]}'
        with self.assertRaises(ContractSetError):
            verify_contract_set(duplicate_key, {})

        row = {"path": "contracts/a.json", "sha256": "0" * 64, "size_bytes": 1}
        row_b = {"path": "contracts/b.json", "sha256": "0" * 64, "size_bytes": 1}
        for rows in ([row_b, row],
                     [{"path": "contracts/../escape", "sha256": "0" * 64, "size_bytes": 1}]):
            raw = json.dumps({"schema": 1, "files": rows}).encode()
            with self.subTest(rows=rows), self.assertRaises(ContractSetError):
                verify_contract_set(raw, {})


if __name__ == "__main__":
    unittest.main()
