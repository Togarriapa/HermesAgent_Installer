from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from hermes_installer.authority.enrollment import (
    AUTHORITY_CONFIG_PATH, CREDENTIAL_DIRECTORY, RootCredentialVault,
    _reject_secret_material, _unique_pairs, write_authority_config,
    write_protected_file,
)
from hermes_installer.authority.types import AuthorityDenied


class ProtectedEnrollmentContracts(unittest.TestCase):
    def test_duplicate_json_keys_and_secret_values_are_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"schema":1,"schema":2}', object_pairs_hook=_unique_pairs)
        with self.assertRaises(AuthorityDenied):
            _reject_secret_material({"provider": {"access_token": "never-store"}})
        with self.assertRaises(AuthorityDenied):
            write_authority_config({"schema": 1, "bearer_token": "not-a-reference"})

    def test_writer_rejects_non_enrolled_path_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "unrelated"
            target.write_bytes(b"keep")
            with self.assertRaises(AuthorityDenied):
                write_protected_file(target, b"replace")
            self.assertEqual(target.read_bytes(), b"keep")

    def test_loaders_and_vault_cannot_be_repointed_to_worker_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                RootCredentialVault(Path(tmp), expected_uid=0)
            with self.assertRaises(ValueError):
                from hermes_installer.authority.enrollment import load_protected_enrollment
                load_protected_enrollment(Path(tmp) / "authority.json")
        self.assertEqual(AUTHORITY_CONFIG_PATH, Path("/etc/hermes-installer/authority.json"))
        self.assertEqual(CREDENTIAL_DIRECTORY, Path("/etc/hermes-installer/credentials"))


if __name__ == "__main__":
    unittest.main()
